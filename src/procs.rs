// SPDX-License-Identifier: MIT

//! Process enumeration and victim selection.
//!
//! Linux earlyoom sorts candidates by the kernel's oom_score. macOS has no
//! oom_score, so ranking is purely by memory use (like earlyoom's
//! --sort-by-rss), measured as phys_footprint: RSS leaves out compressed
//! and swapped-out pages, which under pressure are most of a hog's memory.
//! --prefer/--avoid shift a process' effective size by +/-30% of total
//! memory, the same trick earlyoom uses for OOM_SCORE_PREFER/OOM_SCORE_AVOID.

use regex_lite::Regex;
use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, System, UpdateKind};

/// How much of total memory --prefer/--avoid add/subtract from the
/// effective size. Mirrors earlyoom's OOM_SCORE_PREFER=300 (of 1000).
const PREFER_AVOID_FRACTION: f64 = 0.3;

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: i32,
    pub uid: u32,
    /// Physical footprint in KiB (RSS if the footprint is unreadable).
    pub mem_kib: u64,
    pub name: String,
    pub cmdline: String,
    /// mem_kib adjusted by --prefer/--avoid. Used for sorting only.
    pub effective_mem_kib: i64,
}

pub struct SelectOpts<'a> {
    pub prefer: Option<&'a Regex>,
    pub avoid: Option<&'a Regex>,
    pub ignore: Option<&'a Regex>,
    pub ignore_root_user: bool,
    /// Never pick ourselves.
    pub self_pid: i32,
}

fn matches(regex: &Regex, p: &ProcInfo) -> bool {
    regex.is_match(&p.name) || (!p.cmdline.is_empty() && p.cmdline != p.name && regex.is_match(&p.cmdline))
}

/// Compute effective size after prefer/avoid adjustment.
/// `total_kib` is total physical memory.
fn effective_mem(p: &ProcInfo, total_kib: u64, opts: &SelectOpts) -> i64 {
    let mut mem = p.mem_kib as i64;
    let delta = (total_kib as f64 * PREFER_AVOID_FRACTION) as i64;
    if let Some(re) = opts.prefer
        && matches(re, p) {
            mem += delta;
        }
    if let Some(re) = opts.avoid
        && matches(re, p) {
            mem -= delta;
        }
    mem
}

/// Apply the selection rules to a single process. Returns true if the
/// process is a candidate for killing.
fn is_candidate(p: &ProcInfo, opts: &SelectOpts) -> bool {
    // pid 0 = kernel_task, pid 1 = launchd. Never touch them.
    if p.pid <= 1 || p.pid == opts.self_pid {
        return false;
    }
    if opts.ignore_root_user && p.uid == 0 {
        return false;
    }
    // No resident memory: either a zombie, or a process owned by another
    // user that we have no permission to inspect (proc_pidinfo fails).
    // Either way, not a useful victim.
    if p.mem_kib == 0 {
        return false;
    }
    if let Some(re) = opts.ignore
        && matches(re, p) {
            return false;
        }
    true
}

/// Pick the process with the largest effective size.
/// Pure function over the process list so it can be unit-tested.
pub fn select_victim(procs: &[ProcInfo], total_kib: u64, opts: &SelectOpts) -> Option<ProcInfo> {
    let mut victim: Option<ProcInfo> = None;
    for p in procs {
        if !is_candidate(p, opts) {
            continue;
        }
        let mut cur = p.clone();
        cur.effective_mem_kib = effective_mem(p, total_kib, opts);
        match &victim {
            None => victim = Some(cur),
            Some(v) => {
                // Higher effective size wins; ties go to higher raw size,
                // then higher pid (deterministic).
                let better = cur.effective_mem_kib > v.effective_mem_kib
                    || (cur.effective_mem_kib == v.effective_mem_kib
                        && (cur.mem_kib > v.mem_kib
                            || (cur.mem_kib == v.mem_kib && cur.pid > v.pid)));
                if better {
                    victim = Some(cur);
                }
            }
        }
    }
    victim
}

/// phys_footprint in KiB: what Activity Monitor calls "Memory", including
/// compressed and swapped pages. None for processes we may not inspect.
fn footprint_kib(pid: i32) -> Option<u64> {
    let mut ri = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
    let res = unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V2,
            ri.as_mut_ptr() as *mut libc::rusage_info_t,
        )
    };
    if res != 0 {
        return None;
    }
    Some(unsafe { ri.assume_init() }.ri_phys_footprint / 1024)
}

/// Enumerate running processes via libproc (through the sysinfo crate).
/// `sys` is reused across calls to avoid reallocation.
pub fn scan_processes(sys: &mut System) -> Vec<ProcInfo> {
    // refresh_processes()'s default kind does not include cmd/user, so use
    // the _specifics variant with exactly what we need.
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_memory()
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet),
    );
    sys.processes()
        .values()
        .filter(|p| !matches!(p.status(), ProcessStatus::Zombie | ProcessStatus::Dead))
        .map(|p| ProcInfo {
            pid: p.pid().as_u32() as i32,
            uid: p.user_id().map(|u| **u).unwrap_or(u32::MAX),
            mem_kib: footprint_kib(p.pid().as_u32() as i32).unwrap_or(p.memory() / 1024),
            name: p.name().to_string_lossy().into_owned(),
            cmdline: p
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" "),
            effective_mem_kib: 0,
        })
        .collect()
}

/// Refresh a single pid; returns false if the process is gone or a zombie.
pub fn is_alive(sys: &mut System, pid: i32) -> bool {
    let sysinfo_pid = Pid::from_u32(pid as u32);
    if sys
        .refresh_processes(sysinfo::ProcessesToUpdate::Some(&[sysinfo_pid]), false)
        == 0
    {
        return false;
    }
    match sys.process(sysinfo_pid) {
        None => false,
        Some(p) => !matches!(p.status(), ProcessStatus::Zombie | ProcessStatus::Dead),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOTAL_KIB: u64 = 10 * 1024 * 1024; // 10 GiB

    fn proc(pid: i32, uid: u32, mem_kib: u64, name: &str) -> ProcInfo {
        ProcInfo {
            pid,
            uid,
            mem_kib,
            name: name.to_string(),
            cmdline: format!("/usr/bin/{}", name),
            effective_mem_kib: 0,
        }
    }

    fn opts() -> SelectOpts<'static> {
        SelectOpts {
            prefer: None,
            avoid: None,
            ignore: None,
            ignore_root_user: false,
            self_pid: -1,
        }
    }

    /// For every pair (i, j): the process listed later must win.
    /// Mirrors permute_is_larger() in testsuite_unit_test.go.
    fn check_ordering(procs: &[ProcInfo], opts: &SelectOpts) {
        for (i, small) in procs.iter().enumerate() {
            for (j, big) in procs.iter().enumerate() {
                let v = select_victim(&[small.clone(), big.clone()], TOTAL_KIB, opts);
                let want = if j > i { big.pid } else { small.pid };
                assert_eq!(
                    v.map(|v| v.pid),
                    Some(want),
                    "pair ({}, {})",
                    small.pid,
                    big.pid
                );
            }
        }
    }

    #[test]
    fn largest_wins() {
        let procs = [
            proc(100, 501, 1234, "a"),
            proc(101, 501, 1238, "b"),
            proc(102, 501, 4 * 1024, "c"),
            proc(103, 501, 10 * 1024 * 1024, "d"),
        ];
        check_ordering(&procs, &opts());
    }

    #[test]
    fn prefer_beats_bigger() {
        let prefer = Regex::new("^preferme$").unwrap();
        let mut o = opts();
        o.prefer = Some(&prefer);
        // prefer adds 30% of 10 GiB = 3 GiB: 2 GiB + 3 GiB > 4 GiB.
        let procs = [
            proc(100, 501, 4 * 1024 * 1024, "hog"),
            proc(101, 501, 2 * 1024 * 1024, "preferme"),
        ];
        check_ordering(&procs, &o);
    }

    #[test]
    fn avoid_loses_to_smaller() {
        let avoid = Regex::new("^avoidme$").unwrap();
        let mut o = opts();
        o.avoid = Some(&avoid);
        // avoid subtracts 30% of 10 GiB = 3 GiB: 2 GiB - 3 GiB < 1 GiB.
        let procs = [
            proc(100, 501, 2 * 1024 * 1024, "avoidme"),
            proc(101, 501, 1 * 1024 * 1024, "normal"),
        ];
        check_ordering(&procs, &o);
    }

    #[test]
    fn ignore_skips() {
        let ignore = Regex::new("^ignoreme$").unwrap();
        let mut o = opts();
        o.ignore = Some(&ignore);
        let procs = [
            proc(100, 501, 1 * 1024 * 1024, "normal"),
            proc(101, 501, 10 * 1024 * 1024, "ignoreme"),
        ];
        // The 10 GiB process is ignored, so the 1 GiB process wins.
        assert_eq!(
            select_victim(&procs, TOTAL_KIB, &o).map(|v| v.pid),
            Some(100)
        );
    }

    #[test]
    fn cmdline_match() {
        // Regex that matches only the cmdline of the smaller process.
        let prefer = Regex::new("chrome-headless").unwrap();
        let mut o = opts();
        o.prefer = Some(&prefer);
        let mut small = proc(101, 501, 2 * 1024 * 1024, "renderer");
        small.cmdline = "/opt/chrome-headless --screenshot".to_string();
        // 2 GiB + 3 GiB prefer bonus > 4 GiB.
        let procs = [proc(100, 501, 4 * 1024 * 1024, "hog"), small];
        check_ordering(&procs, &o);
    }

    #[test]
    fn skip_protected() {
        let mut o = opts();
        o.self_pid = 999;
        o.ignore_root_user = true;
        let procs = [
            proc(0, 0, 90 * 1024 * 1024, "kernel_task"),
            proc(1, 0, 90 * 1024 * 1024, "launchd"),
            proc(50, 0, 90 * 1024 * 1024, "rootd"),     // root-owned
            proc(999, 501, 90 * 1024 * 1024, "myself"), // self
            proc(101, 501, 0, "zombie-ish"),            // mem=0
            proc(102, 501, 1024, "victim"),
        ];
        // Everything else is excluded; "victim" is the only choice.
        assert_eq!(
            select_victim(&procs, TOTAL_KIB, &o).map(|v| v.pid),
            Some(102)
        );
    }
}
