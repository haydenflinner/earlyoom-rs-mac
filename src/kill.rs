// SPDX-License-Identifier: MIT

//! Kill the selected victim: SIGTERM first, escalate to SIGKILL if memory
//! keeps shrinking, plus notifications and hooks.

use std::io;
use std::process::Command;
use std::time::{Duration, Instant};

use sysinfo::System;

use crate::args::Args;
use crate::meminfo::{self, MemInfo};
use crate::procs::{self, ProcInfo};
use crate::{debug, info, warn};

/// Poll interval while waiting for a killed process to exit.
const POLL_MS: u64 = 100;
/// Give up waiting for exit after this long.
const KILL_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
/// Give the -P pre-hook a moment to start before we send the signal.
const PREHOOK_STARTUP_SLEEP: Duration = Duration::from_millis(200);
/// Rate limit for --dryrun notifications (seconds).
const NOTIFY_RATELIMIT_SECS: u64 = 1;

/// Send `sig` to `pid` (or, with -g, to its whole process group).
fn send_signal(args: &Args, pid: i32, sig: libc::c_int) -> io::Result<()> {
    if args.kill_group {
        let pgid = unsafe { libc::getpgid(pid) };
        if pgid < 0 {
            return Err(io::Error::last_os_error());
        }
        warn(&format!(
            "killing whole process group {} (-g flag is active)",
            pgid
        ));
        if unsafe { libc::killpg(pgid, sig) } != 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(());
    }
    if unsafe { libc::kill(pid, sig) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Send `sig` to `pid`, then wait up to 10s for it to exit, escalating to
/// SIGKILL if the memory situation drops below the SIGKILL thresholds.
/// `sig == 0` is a no-op self-test: send nothing, return immediately.
pub fn kill_wait(sys: &mut System, args: &Args, pid: i32, mut sig: libc::c_int) -> io::Result<()> {
    if args.dryrun && sig != 0 {
        warn("dryrun, not actually sending any signal");
        return Ok(());
    }
    if sig == 0 {
        return Ok(());
    }

    send_signal(args, pid, sig)?;

    let start = Instant::now();
    while start.elapsed() < KILL_WAIT_TIMEOUT {
        std::thread::sleep(Duration::from_millis(POLL_MS));
        let secs = start.elapsed().as_secs_f32();

        // We sent SIGTERM but have now dropped below SIGKILL limits.
        // Escalate to SIGKILL.
        if sig != libc::SIGKILL {
            match meminfo::parse_meminfo() {
                Ok(m) if below_kill_limits(args, &m) => {
                    sig = libc::SIGKILL;
                    warn(&format!("escalating to SIGKILL after {:.3} seconds", secs));
                    send_signal(args, pid, sig)?;
                }
                Ok(m) => debug(&format!(
                    "waiting for pid {}: {}",
                    pid,
                    mem_stats_line(&m)
                )),
                Err(_) => {}
            }
        }
        if !procs::is_alive(sys, pid) {
            warn(&format!("process {} exited after {:.3} seconds", pid, secs));
            return Ok(());
        }
    }

    warn(&format!("process {} did not exit", pid));
    Err(io::Error::new(io::ErrorKind::TimedOut, "process did not exit"))
}

/// Spawn a helper program and let a background thread reap it.
/// Used for notifications and hooks so we never block on them.
fn spawn_reaped(mut cmd: Command) {
    match cmd.spawn() {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => warn(&format!("spawn {:?} failed: {}", cmd.get_program(), e)),
    }
}

fn add_victim_env(cmd: &mut Command, victim: &ProcInfo) {
    cmd.env("EARLYOOM_PID", victim.pid.to_string())
        .env("EARLYOOM_UID", victim.uid.to_string())
        .env("EARLYOOM_NAME", &victim.name)
        .env("EARLYOOM_CMDLINE", &victim.cmdline)
        .env("EARLYOOM_VM_RSS_MB", (victim.rss_kib / 1024).to_string());
}

/// "-n" option: macOS notification via osascript.
fn notify_osascript(body: &str) {
    // Escape characters that would break the AppleScript string literal.
    let escaped = body.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "display notification \"{}\" with title \"earlyoom\"",
        escaped
    );
    let mut cmd = Command::new("/usr/bin/osascript");
    cmd.args(["-e", &script]);
    spawn_reaped(cmd);
}

/// "-N" option: call a user script after a kill.
fn notify_ext(script: &str, victim: &ProcInfo) {
    let mut cmd = Command::new(script);
    add_victim_env(&mut cmd, victim);
    spawn_reaped(cmd);
}

/// Send a notification if -n is set. Used for error reporting too.
pub fn notify(args: &Args, body: &str) {
    if args.notify {
        notify_osascript(body);
    }
}

fn notify_process_killed(args: &Args, victim: &ProcInfo) {
    if !args.notify && args.notify_ext.is_none() {
        return;
    }
    // In dryrun mode nothing changes the situation, so rate-limit
    // notifications to avoid spamming.
    if args.dryrun {
        static PREV: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
        let mut prev = PREV.lock().unwrap();
        if prev
            .map(|t| t.elapsed().as_secs() < NOTIFY_RATELIMIT_SECS)
            .unwrap_or(false)
        {
            debug("notify: rate limit hit, skipping");
            return;
        }
        *prev = Some(Instant::now());
    }
    if args.notify {
        notify_osascript(&format!(
            "Low memory! Killing process {} {}",
            victim.pid, victim.name
        ));
    }
    if let Some(script) = &args.notify_ext {
        notify_ext(script, victim);
    }
}

/// "-P" option: run a program before killing a process.
fn run_prehook(args: &Args, victim: &ProcInfo) {
    if let Some(hook) = &args.prehook {
        debug(&format!("going to invoke program before killing: {}", hook));
        let mut cmd = Command::new(hook);
        add_victim_env(&mut cmd, victim);
        spawn_reaped(cmd);
        // Give the helper a brief moment to start and do something
        // meaningful before we send the signal.
        std::thread::sleep(PREHOOK_STARTUP_SLEEP);
    }
}

pub fn below_term_limits(args: &Args, m: &MemInfo) -> bool {
    m.mem_available_percent <= args.mem_term_percent
        && m.swap_free_percent <= args.swap_term_percent
}

pub fn below_kill_limits(args: &Args, m: &MemInfo) -> bool {
    m.mem_available_percent <= args.mem_kill_percent
        && m.swap_free_percent <= args.swap_kill_percent
}

pub fn mem_stats_line(m: &MemInfo) -> String {
    format!(
        "mem avail: {:5} of {:5} MiB ({:5.2}%), swap free: {:4} of {:4} MiB ({:5.2}%)",
        m.mem_available_kib / 1024,
        m.user_mem_total_kib / 1024,
        m.mem_available_percent,
        m.swap_free_kib / 1024,
        m.swap_total_kib / 1024,
        m.swap_free_percent,
    )
}

fn sig_name(sig: libc::c_int) -> &'static str {
    match sig {
        libc::SIGTERM => "SIGTERM",
        libc::SIGKILL => "SIGKILL",
        0 => "0 (no-op signal)",
        _ => "?",
    }
}

/// Kill the victim, wait for it to exit, send a notification if enabled.
pub fn kill_process(sys: &mut System, args: &Args, sig: libc::c_int, victim: &ProcInfo) {
    let sig_name = sig_name(sig);
    warn(&format!(
        "sending {} to process {} uid {} \"{}\": VmRSS {} MiB, cmdline \"{}\"",
        sig_name,
        victim.pid,
        victim.uid,
        victim.name,
        victim.rss_kib / 1024,
        victim.cmdline,
    ));

    if sig != 0 {
        run_prehook(args, victim);
    }

    let res = kill_wait(sys, args, victim.pid, sig);

    // Notify AFTER the kill: at that point memory has been freed, so the
    // helper is more likely to be able to spawn.
    if sig != 0 {
        notify_process_killed(args, victim);
    }
    if sig == 0 {
        return;
    }

    if let Err(e) = res {
        warn(&format!("kill failed: {}", e));
        if args.notify {
            notify_osascript("Error: Failed to kill process");
        }
        // Killing may have failed because we lack permission. Retrying
        // immediately would just spam the log.
        if e.raw_os_error() == Some(libc::EPERM) {
            warn("sleeping 1 second");
            std::thread::sleep(Duration::from_secs(1));
        }
    } else if args.notify {
        info("process killed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::Args;

    fn test_args() -> Args {
        Args {
            mem_term_percent: 10.0,
            mem_kill_percent: 5.0,
            swap_term_percent: 10.0,
            swap_kill_percent: 5.0,
            report_interval_ms: 0,
            notify: false,
            notify_ext: None,
            prehook: None,
            kill_group: false,
            ignore_root_user: false,
            prefer: None,
            avoid: None,
            ignore: None,
            dryrun: false,
            set_my_priority: false,
        }
    }

    /// Send SIGTERM to a real `sleep` process and check that kill_wait
    /// returns once it is gone (also covers zombie detection in is_alive,
    /// since our child stays a zombie until we wait() for it).
    #[test]
    fn kill_wait_terminates() {
        let mut sys = System::new();
        let mut child = Command::new("sleep").arg("60").spawn().unwrap();
        let pid = child.id() as i32;
        kill_wait(&mut sys, &test_args(), pid, libc::SIGTERM).unwrap();
        assert!(!procs::is_alive(&mut sys, pid));
        let _ = child.wait();
    }

    /// In dryrun mode nothing is sent and the victim stays alive.
    #[test]
    fn dryrun_sends_nothing() {
        let mut sys = System::new();
        let mut child = Command::new("sleep").arg("60").spawn().unwrap();
        let pid = child.id() as i32;
        let mut args = test_args();
        args.dryrun = true;
        kill_wait(&mut sys, &args, pid, libc::SIGTERM).unwrap();
        assert!(procs::is_alive(&mut sys, pid));
        let _ = child.kill();
        let _ = child.wait();
    }
}
