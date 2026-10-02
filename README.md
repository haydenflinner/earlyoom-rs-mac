# earlyoom-rs-mac

A Rust implementation of [earlyoom](https://github.com/rfjakob/earlyoom) for
macOS. It watches available memory and swap, and kills the largest process
*before* the system grinds to a halt — memory compression, swap thrashing and
a beachballing desktop.

Written for the classic Mac dev problem: orphaned test-browser binaries and
hungry build jobs (`cargo`, `rustc`, `clang`) eating all of RAM.

## Quick start

```console
cargo build --release
cargo run --release -- -m 12 --prefer 'cargo|rustc|clang|ld64|ld|lld' --avoid 'chrome|WindowServer|loginwindow' -n
```

This sends SIGTERM to the biggest memory hog once uncompressed-available
memory drops below 12 % (and free swap below 10 %), escalates to SIGKILL at
half of that, prefers killing compilers/linkers, avoids killing Chrome and
the window server, and posts a macOS notification on each kill.

Try it safely first:

```console
cargo run --release -- --dryrun -d
```

## Usage

```
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
```

`--prefer` and `--avoid` shift a process' effective RSS by ±30 % of total
memory (mirroring earlyoom's `OOM_SCORE_PREFER`/`OOM_SCORE_AVOID`).

The `-N` hook script receives `EARLYOOM_PID`, `EARLYOOM_UID`,
`EARLYOOM_NAME`, `EARLYOOM_CMDLINE` and `EARLYOOM_VM_RSS_MB` in its
environment, like upstream earlyoom.

## Autostart with launchd

A LaunchAgent template is included (`com.earlyoom.earlyoom.plist`).
Running as your user is enough to kill your own processes — no root needed:

```console
install -m 755 target/release/earlyoom /usr/local/bin/earlyoom
cp com.earlyoom.earlyoom.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.earlyoom.earlyoom.plist
```

Logs go to `/tmp/earlyoom.{out,err}.log`. Edit the plist's
`ProgramArguments` to enable your preferred flags.

## How it works

* Available memory is computed as Apple's `AVAILABLE_NON_COMPRESSED_MEMORY`
  = active + inactive + free + speculative pages (see xnu
  `doc/vm/memorystatus_notify.md`). It drops exactly when the VM compressor
  and swapper start working — the "system grinding" moment.
* Swap comes from the `vm.swapusage` sysctl.
* Processes are enumerated via `libproc` (`proc_pidinfo`/`KERN_PROCARGS2`).
* macOS has no `oom_score`; the victim is simply the process with the
  largest RSS, adjusted by `--prefer`/`--avoid`.

## Differences vs. Linux earlyoom

* No `oom_score` / `oom_score_adj` — RSS ranking only.
* `--kernel-oom` does not exist (no sysrq-trigger).
* `mlockall()` is not implemented on macOS; there is no way to lock the
  daemon into RAM.
* Notifications use `osascript` instead of D-Bus.
* `kernel_task` (pid 0) and `launchd` (pid 1) are never killed.
* Without root, processes owned by other users can't be inspected or
  signaled and are skipped automatically.

## Caveats

* Without `--avoid`, the largest RSS process may be something you don't want
  to lose (WindowServer logs you out when killed).
* SIP-protected processes can't be killed even as root; that's fine, they
  just show up as kill failures in the log.

## License

MIT, same as [earlyoom](https://github.com/rfjakob/earlyoom). This is an
independent re-implementation for macOS.
