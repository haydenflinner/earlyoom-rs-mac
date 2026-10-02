// SPDX-License-Identifier: MIT

//! earlyoom for macOS: check available memory and swap in a loop and kill
//! the largest process when they get too low.
//!
//! Ported from https://github.com/rfjakob/earlyoom (Linux) to macOS.

mod args;
mod kill;
mod meminfo;
mod procs;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sysinfo::System;

use args::Args;
use meminfo::MemInfo;
use procs::SelectOpts;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_debug(v: bool) {
    DEBUG_ENABLED.store(v, Ordering::Relaxed);
}

fn tty_color(fd: libc::c_int) -> bool {
    std::env::var_os("NO_COLOR").is_none() && unsafe { libc::isatty(fd) } == 1
}

/// Info message to stdout.
pub fn info(msg: &str) {
    println!("{}", msg);
}

/// Warning message to stderr (yellow on a tty).
pub fn warn(msg: &str) {
    if tty_color(libc::STDERR_FILENO) {
        eprintln!("\x1b[33m{}\x1b[0m", msg);
    } else {
        eprintln!("{}", msg);
    }
}

/// Debug message to stdout (gray on a tty), only with -d/--debug.
pub fn debug(msg: &str) {
    if !DEBUG_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    if tty_color(libc::STDOUT_FILENO) {
        println!("\x1b[2m{}\x1b[0m", msg);
    } else {
        println!("{}", msg);
    }
}

fn fatal(code: i32, msg: &str) -> ! {
    if tty_color(libc::STDERR_FILENO) {
        eprintln!("\x1b[31mfatal: {}\x1b[0m", msg);
    } else {
        eprintln!("fatal: {}", msg);
    }
    std::process::exit(code);
}

/// Calculate how long we can sleep based on distance from the limits.
/// Ported from sleep_time_ms() in main.c.
fn sleep_time_ms(args: &Args, m: &MemInfo) -> u64 {
    // Max expected memory/swap fill rate, KiB per ms (~= MiB per s).
    const MEM_FILL_RATE: f64 = 6000.0;
    const SWAP_FILL_RATE: f64 = 800.0;
    const MIN_SLEEP: u64 = 100;
    const MAX_SLEEP: u64 = 1000;

    let mem_headroom = ((m.mem_available_percent - args.mem_term_percent)
        * m.user_mem_total_kib as f64
        / 100.0)
        .max(0.0);
    let swap_headroom = ((m.swap_free_percent - args.swap_term_percent)
        * m.swap_total_kib as f64
        / 100.0)
        .max(0.0);
    let ms = (mem_headroom / MEM_FILL_RATE + swap_headroom / SWAP_FILL_RATE) as u64;
    ms.clamp(MIN_SLEEP, MAX_SLEEP)
}

/// Which signal the current memory situation warrants.
fn lowmem_sig(args: &Args, m: &MemInfo) -> libc::c_int {
    if kill::below_kill_limits(args, m) {
        libc::SIGKILL
    } else if kill::below_term_limits(args, m) {
        libc::SIGTERM
    } else {
        0
    }
}

fn check_hook_path(flag: &str, path: &mut Option<String>) {
    if let Some(p) = path {
        if !p.starts_with('/') {
            warn(&format!(
                "{}: '{}' is not an absolute path, disabling {}",
                flag, p, flag
            ));
            *path = None;
        } else if !is_executable(p) {
            warn(&format!("{}: '{}' is not executable", flag, p));
        }
    }
}

fn is_executable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|md| md.is_file() && md.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Main event loop. Never returns.
fn poll_loop(args: &Args) -> ! {
    let mut sys = System::new();
    // Print a memory report when this reaches zero. Starts at zero so the
    // first report prints immediately.
    let mut report_countdown_ms: i64 = 0;

    loop {
        let m = match meminfo::parse_meminfo() {
            Ok(m) => m,
            Err(e) => fatal(103, &format!("could not read memory statistics: {}", e)),
        };
        let sig = lowmem_sig(args, &m);

        if sig == libc::SIGKILL {
            warn(&kill::mem_stats_line(&m));
            warn(&format!(
                "low memory! at or below SIGKILL limits: mem {:5.2}%, swap {:5.2}%",
                args.mem_kill_percent, args.swap_kill_percent
            ));
        } else if sig == libc::SIGTERM {
            warn(&kill::mem_stats_line(&m));
            warn(&format!(
                "low memory! at or below SIGTERM limits: mem {:5.2}%, swap {:5.2}%",
                args.mem_term_percent, args.swap_term_percent
            ));
        }

        if sig != 0 {
            let procs = procs::scan_processes(&mut sys);
            debug(&format!("{} candidate processes", procs.len()));
            let opts = SelectOpts {
                prefer: args.prefer.as_ref(),
                avoid: args.avoid.as_ref(),
                ignore: args.ignore.as_ref(),
                ignore_root_user: args.ignore_root_user,
                self_pid: std::process::id() as i32,
            };
            let victim = procs::select_victim(&procs, m.mem_total_kib, &opts);

            // Scanning processes takes long enough that the situation may
            // have changed. Double-check before killing.
            let m2 = meminfo::parse_meminfo().unwrap_or(m);
            if lowmem_sig(args, &m2) == 0 {
                warn("memory situation has recovered while selecting victim");
            } else {
                match victim {
                    Some(v) => {
                        kill::kill_process(&mut sys, args, sig, &v);
                    }
                    None => {
                        warn("Could not find a process to kill. Sleeping 1 second.");
                        kill::notify(
                            args,
                            "Error: Could not find a process to kill. Sleeping 1 second.",
                        );
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            }
        } else if args.report_interval_ms > 0 && report_countdown_ms <= 0 {
            info(&kill::mem_stats_line(&m));
            report_countdown_ms = args.report_interval_ms;
        }

        let sleep_ms = sleep_time_ms(args, &m);
        debug(&format!("adaptive sleep time: {} ms", sleep_ms));
        std::thread::sleep(Duration::from_millis(sleep_ms));
        report_countdown_ms -= sleep_ms as i64;
    }
}

fn main() {
    // Line-buffered output is the default; nothing to set up in Rust.
    eprintln!("earlyoom {} (macOS)", VERSION);

    let m = match meminfo::parse_meminfo() {
        Ok(m) => m,
        Err(e) => fatal(102, &format!("could not read memory statistics: {}", e)),
    };

    let mut args = args::parse_args(&m, "earlyoom");

    check_hook_path("-N", &mut args.notify_ext);
    check_hook_path("-P", &mut args.prehook);

    if args.set_my_priority {
        let res = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, -20) };
        if res != 0 {
            warn(&format!(
                "Could not set priority: {}. Continuing anyway",
                std::io::Error::last_os_error()
            ));
        } else {
            eprintln!("Priority was raised successfully");
        }
    }

    // Print memory limits.
    eprintln!(
        "mem total: {:4} MiB, user mem total: {:4} MiB, swap total: {:4} MiB",
        m.mem_total_kib / 1024,
        m.user_mem_total_kib / 1024,
        m.swap_total_kib / 1024
    );
    debug(&format!(
        "anon pages: {} MiB, uncompressed available: {} MiB",
        m.anon_pages_kib / 1024,
        m.mem_available_kib / 1024
    ));
    eprintln!(
        "sending SIGTERM when mem avail <= {:5.2}% and swap free <= {:5.2}%,",
        args.mem_term_percent, args.swap_term_percent
    );
    eprintln!(
        "        SIGKILL when mem avail <= {:5.2}% and swap free <= {:5.2}%",
        args.mem_kill_percent, args.swap_kill_percent
    );

    // Note: Linux earlyoom calls mlockall() here so it cannot be swapped out
    // when memory runs out. macOS does not implement mlockall() (ENOSYS), so
    // there is no equivalent.

    poll_loop(&args);
}
