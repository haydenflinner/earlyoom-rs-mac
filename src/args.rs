// SPDX-License-Identifier: MIT

//! Command-line parsing, mirroring earlyoom's interface.

use pico_args::Arguments;
use regex_lite::Regex;

use crate::meminfo::MemInfo;
use crate::warn;

pub struct Args {
    /// If available memory AND free swap drop below these percentages of
    /// their totals, we start killing processes.
    pub mem_term_percent: f64,
    pub mem_kill_percent: f64,
    pub swap_term_percent: f64,
    pub swap_kill_percent: f64,
    /// Memory report interval, milliseconds. 0 disables reporting.
    pub report_interval_ms: i64,
    /// Enable macOS notifications via osascript (-n).
    pub notify: bool,
    /// Script run after each kill (-N).
    pub notify_ext: Option<String>,
    /// Program run before each kill (-P).
    pub prehook: Option<String>,
    /// Kill the whole process group (-g).
    pub kill_group: bool,
    /// Do not kill processes owned by root.
    pub ignore_root_user: bool,
    /// prefer/avoid/ignore these processes. None = no-op.
    pub prefer: Option<Regex>,
    pub avoid: Option<Regex>,
    pub ignore: Option<Regex>,
    /// Don't actually kill anything.
    pub dryrun: bool,
    /// Raise our scheduling priority (-p).
    pub set_my_priority: bool,
}

fn fatal(code: i32, msg: &str) -> ! {
    eprintln!("fatal: {}", msg);
    std::process::exit(code);
}

/// Parse a single tuple component. Range: 0 <= val <= upper_limit.
fn parse_part(part: &str, upper_limit: f64) -> Result<f64, String> {
    let val: f64 = part
        .parse()
        .map_err(|_| format!("conversion error in '{}'", part))?;
    if !val.is_finite() {
        return Err(format!("value '{}' is not finite", part));
    }
    if val > upper_limit {
        return Err(format!("value {} exceeds limit {}", val, upper_limit));
    }
    if val < 0.0 {
        return Err(format!("value {} below zero", val));
    }
    Ok(val)
}

/// Parse the "term[,kill]" tuple. Examples: "123", "123,456".
/// Returns (term, kill). Ported from parse_term_kill_tuple() in msg.c.
pub fn parse_term_kill_tuple(optarg: &str, upper_limit: f64) -> Result<(f64, f64), String> {
    // The C version reads optarg into a 255-byte buffer.
    if optarg.len() > 255 {
        return Err(format!("argument too long ({} bytes)", optarg.len()));
    }
    let mut parts = optarg.splitn(2, ',');
    let part1 = parts.next().unwrap_or("");
    let part2 = parts.next();

    let mut term = parse_part(part1, upper_limit)?;
    let kill = match part2 {
        Some(p) => parse_part(p, upper_limit)?,
        // User passed only the SIGTERM value: SIGKILL = SIGTERM/2.
        None => term / 2.0,
    };
    // Setting term < kill makes no sense.
    if term < kill {
        warn(&format!(
            "warning: SIGTERM value {:.2} is below SIGKILL value {:.2}, setting SIGTERM = SIGKILL = {:.2}",
            term, kill, kill
        ));
        term = kill;
    }
    if term == 0.0 && kill == 0.0 {
        return Err("both SIGTERM and SIGKILL values are zero".to_string());
    }
    Ok((term, kill))
}

const HELP: &str = "\
Usage: earlyoom [OPTION]...

  -m PERCENT[,KILL_PERCENT] set available memory minimum to PERCENT of total
                            (default 10 %).
                            earlyoom sends SIGTERM once below PERCENT, then
                            SIGKILL once below KILL_PERCENT (default PERCENT/2).
  -s PERCENT[,KILL_PERCENT] set free swap minimum to PERCENT of total (default
                            10 %).
                            Note: both memory and swap must be below minimum for
                            earlyoom to act.
  -M SIZE[,KILL_SIZE]       set available memory minimum to SIZE KiB
  -S SIZE[,KILL_SIZE]       set free swap minimum to SIZE KiB
  -n                        enable notifications via osascript
  -N /PATH/TO/SCRIPT        call script after oom kill
  -g                        kill all processes within a process group
  -d, --debug               enable debugging messages
  -v                        print version information and exit
  -r INTERVAL               memory report interval in seconds (default 1), set
                            to 0 to disable completely
  -p                        set niceness of earlyoom to -20
  --ignore-root-user        do not kill processes owned by root
  --prefer REGEX            prefer to kill processes matching REGEX
                            (matched against process name and command line)
  --avoid REGEX             avoid killing processes matching REGEX
  --ignore REGEX            ignore processes matching REGEX
  --dryrun                  dry run (do not kill any processes)
  -h, --help                this help text

macOS notes:
  * There is no oom_score on macOS; victims are chosen by RSS
    (like --sort-by-rss on Linux).
  * kernel_task (pid 0) and launchd (pid 1) are never killed.
  * --kernel-oom does not exist on macOS.
";

pub fn parse_args(m: &MemInfo, argv0: &str) -> Args {
    let _ = argv0;
    let mut pa = Arguments::from_env();

    if pa.contains(["-h", "--help"]) {
        eprint!("{}", HELP);
        std::process::exit(0);
    }
    if pa.contains("-v") {
        // version already printed at startup
        std::process::exit(0);
    }

    let mut args = Args {
        mem_term_percent: 10.0,
        mem_kill_percent: 5.0,
        swap_term_percent: 10.0,
        swap_kill_percent: 5.0,
        report_interval_ms: 1000,
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
    };

    // Compatibility: flags that exist in Linux earlyoom but are ignored or
    // unsupported here.
    if pa.contains("-k") {
        eprintln!("Option -k is ignored since earlyoom v1.2");
    }
    if pa.contains("-i") {
        eprintln!("Option -i is ignored since earlyoom v1.7");
    }
    if pa.contains("--kernel-oom") {
        fatal(13, "--kernel-oom is not supported on macOS (no sysrq-trigger)");
    }
    if pa.contains("--sort-by-rss") {
        eprintln!("--sort-by-rss: RSS is the only sort criterion on macOS");
    }
    if pa.contains("--syslog") {
        eprintln!("--syslog: not supported on macOS, logging to stderr/stdout");
    }

    // -m PERCENT[,KILL]
    let have_m = match pa.opt_value_from_str::<&str, String>("-m") {
        Ok(Some(v)) => match parse_term_kill_tuple(&v, 99.0) {
            Ok((t, k)) => {
                args.mem_term_percent = t;
                args.mem_kill_percent = k;
                true
            }
            Err(e) => fatal(15, &format!("-m: {}", e)),
        },
        Ok(None) => false,
        Err(e) => fatal(15, &format!("-m: {}", e)),
    };
    // -s PERCENT[,KILL]
    let have_s = match pa.opt_value_from_str::<&str, String>("-s") {
        Ok(Some(v)) => match parse_term_kill_tuple(&v, 100.0) {
            Ok((t, k)) => {
                args.swap_term_percent = t;
                args.swap_kill_percent = k;
                true
            }
            Err(e) => fatal(16, &format!("-s: {}", e)),
        },
        Ok(None) => false,
        Err(e) => fatal(16, &format!("-s: {}", e)),
    };
    // -M KiB[,KILL_KiB]
    let have_mm = match pa.opt_value_from_str::<&str, String>("-M") {
        Ok(Some(v)) => {
            let limit = m.mem_total_kib as f64 * 100.0 / 99.0;
            match parse_term_kill_tuple(&v, limit) {
                Ok(t) => Some(t),
                Err(e) => fatal(15, &format!("-M: {}", e)),
            }
        }
        Ok(None) => None,
        Err(e) => fatal(15, &format!("-M: {}", e)),
    };
    // -S KiB[,KILL_KiB]
    let have_ss = match pa.opt_value_from_str::<&str, String>("-S") {
        Ok(Some(v)) => {
            if m.swap_total_kib == 0 {
                eprintln!("warning: -S: total swap is zero, using default percentages");
                None
            } else {
                let limit = m.swap_total_kib as f64 * 100.0 / 99.0;
                match parse_term_kill_tuple(&v, limit) {
                    Ok(t) => Some(t),
                    Err(e) => fatal(16, &format!("-S: {}", e)),
                }
            }
        }
        Ok(None) => None,
        Err(e) => fatal(16, &format!("-S: {}", e)),
    };

    // Merge KiB values with percent values (lower wins), like upstream.
    if let Some((term_kib, kill_kib)) = have_mm {
        let term_pct = 100.0 * term_kib / m.mem_total_kib as f64;
        let kill_pct = 100.0 * kill_kib / m.mem_total_kib as f64;
        if have_m {
            args.mem_term_percent = args.mem_term_percent.min(term_pct);
            args.mem_kill_percent = args.mem_kill_percent.min(kill_pct);
        } else {
            args.mem_term_percent = term_pct;
            args.mem_kill_percent = kill_pct;
        }
    }
    if let Some((term_kib, kill_kib)) = have_ss {
        let term_pct = 100.0 * term_kib / m.swap_total_kib as f64;
        let kill_pct = 100.0 * kill_kib / m.swap_total_kib as f64;
        if have_s {
            args.swap_term_percent = args.swap_term_percent.min(term_pct);
            args.swap_kill_percent = args.swap_kill_percent.min(kill_pct);
        } else {
            args.swap_term_percent = term_pct;
            args.swap_kill_percent = kill_pct;
        }
    }

    if pa.contains("-n") {
        args.notify = true;
        eprintln!("Notifying through osascript");
    }
    if pa.contains("-g") {
        args.kill_group = true;
    }
    args.notify_ext = match pa.opt_value_from_str::<&str, String>("-N") {
        Ok(v) => v,
        Err(e) => fatal(13, &format!("-N: {}", e)),
    };
    args.prehook = match pa.opt_value_from_str::<&str, String>("-P") {
        Ok(v) => v,
        Err(e) => fatal(13, &format!("-P: {}", e)),
    };
    if pa.contains(["-d", "--debug"]) {
        crate::set_debug(true);
    }
    args.report_interval_ms = match pa.opt_value_from_str::<&str, String>("-r") {
        Ok(Some(v)) => {
            let f: f64 = v.parse().unwrap_or(-1.0);
            if f < 0.0 || !f.is_finite() {
                fatal(14, &format!("-r: invalid interval '{}'", v));
            }
            (f * 1000.0) as i64
        }
        Ok(None) => args.report_interval_ms,
        Err(e) => fatal(14, &format!("-r: {}", e)),
    };
    if pa.contains("-p") {
        args.set_my_priority = true;
    }
    if pa.contains("--ignore-root-user") {
        args.ignore_root_user = true;
        eprintln!("Processes owned by root will not be killed");
    }
    args.dryrun = pa.contains("--dryrun");
    if args.dryrun {
        warn("dryrun mode enabled, will not kill anything");
    }

    match pa.opt_value_from_str::<&str, String>("--prefer") {
        Ok(Some(v)) => match Regex::new(&v) {
            Ok(re) => {
                eprintln!("Preferring to kill processes matching regex '{}'", v);
                args.prefer = Some(re);
            }
            Err(e) => fatal(6, &format!("could not compile regex '{}': {}", v, e)),
        },
        Ok(None) => {}
        Err(e) => fatal(6, &format!("--prefer: {}", e)),
    }
    match pa.opt_value_from_str::<&str, String>("--avoid") {
        Ok(Some(v)) => match Regex::new(&v) {
            Ok(re) => {
                eprintln!("Will avoid killing processes matching regex '{}'", v);
                args.avoid = Some(re);
            }
            Err(e) => fatal(6, &format!("could not compile regex '{}': {}", v, e)),
        },
        Ok(None) => {}
        Err(e) => fatal(6, &format!("--avoid: {}", e)),
    }
    match pa.opt_value_from_str::<&str, String>("--ignore") {
        Ok(Some(v)) => match Regex::new(&v) {
            Ok(re) => {
                eprintln!("Will ignore processes matching regex '{}'", v);
                args.ignore = Some(re);
            }
            Err(e) => fatal(6, &format!("could not compile regex '{}': {}", v, e)),
        },
        Ok(None) => {}
        Err(e) => fatal(6, &format!("--ignore: {}", e)),
    }

    // Anything left over is an error.
    let rest = pa.finish();
    if !rest.is_empty() {
        fatal(
            13,
            &format!("extra argument not understood: '{}'", rest[0].to_string_lossy()),
        );
    }

    args
}

#[cfg(test)]
mod tests {
    use super::parse_term_kill_tuple;

    fn ok(s: &str, limit: f64) -> (f64, f64) {
        parse_term_kill_tuple(s, limit).expect(s)
    }

    fn fails(s: &str, limit: f64) {
        assert!(parse_term_kill_tuple(s, limit).is_err(), "case {}", s);
    }

    // Ported from TestParseTuple in testsuite_unit_test.go.
    #[test]
    fn parse_tuple() {
        assert_eq!(ok("2,1", 100.0), (2.0, 1.0));
        assert_eq!(ok("20,10", 100.0), (20.0, 10.0));
        assert_eq!(ok("30", 100.0), (30.0, 15.0));
        fails("30", 20.0);
        fails("22[,20]", 100.0);
        fails("220[,160]", 300.0);
        fails("180[,170]", 300.0);
        assert_eq!(ok("5,0", 100.0), (5.0, 0.0));
        // TERM value is set to KILL value when it is below TERM
        assert_eq!(ok("5,9", 100.0), (9.0, 9.0));
        assert_eq!(ok("0,5", 100.0), (5.0, 5.0));
        assert_eq!(ok("4,5", 100.0), (5.0, 5.0));
        fails("0", 100.0);
        fails("0,0", 100.0);
        // Floating point values
        assert_eq!(ok("4.0,2.0", 100.0), (4.0, 2.0));
        fails("4,0,2,0", 100.0);
        assert_eq!(ok("3.1415,2.7182", 100.0), (3.1415, 2.7182));
        assert_eq!(ok("3.1415", 100.0), (3.1415, 3.1415 / 2.0));
        fails(&format!("1.{}", "123".repeat(100)), 100.0);
        // Leading garbage
        fails("x1,x2", 100.0);
        fails("1,x2", 100.0);
        // Trailing garbage
        fails("1x,2x", 100.0);
        fails("1.1.", 100.0);
        fails("1,2..", 100.0);
        // Negatives and overflows
        fails("-10", 100.0);
        fails("-1", 100.0);
        fails("2147483648", 100.0);
        fails("4294967296", 100.0);
        fails("inf", 100.0);
        fails("NaN", 100.0);
    }
}
