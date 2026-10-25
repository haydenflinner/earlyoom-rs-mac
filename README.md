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
cargo run --release -- --prefer 'cargo|rustc|clang|ld64|ld|lld' --avoid 'chrome|WindowServer|loginwindow' -n
```

This sends SIGTERM to the biggest memory hog once the machine starts
swapping under memory pressure (1 GiB of swap growth), escalates to SIGKILL
at 2 GiB, prefers killing compilers/linkers, avoids killing Chrome and the
window server, and posts a macOS notification on each kill.

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
                            100 %, i.e. off: macOS grows swap on demand).
                            Note: both memory and swap must be below minimum for
                            the memory trigger to act.
  -M SIZE[,KILL_SIZE]       set available memory minimum to SIZE KiB
  -S SIZE[,KILL_SIZE]       set free swap minimum to SIZE KiB
  --swap-grow SIZE[,KILL_SIZE]
                            also act once swap use grows by SIZE MiB while the
                            kernel reports memory pressure (default 1024,2048;
                            KILL_SIZE defaults to 2*SIZE)
  --no-pressure             do not send SIGTERM on critical kernel memory
                            pressure
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

`--prefer` and `--avoid` shift a process' effective size by ±30 % of total
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
launchctl bootstrap "gui/$UID" ~/Library/LaunchAgents/com.earlyoom.earlyoom.plist
```

Do not use `sudo`: a LaunchAgent lives in your `gui/$UID` domain, and the
`system` domain will reject a plist under `~/Library/LaunchAgents`.

To reload after editing the plist or installing a new binary:

```console
launchctl bootout "gui/$UID/com.earlyoom.earlyoom"
launchctl bootstrap "gui/$UID" ~/Library/LaunchAgents/com.earlyoom.earlyoom.plist
```

Logs go to `~/Library/Logs/earlyoom.{out,err}.log` (not `/tmp`, which macOS
clears at boot, taking the post-mortem of a freeze with it). Edit the plist's
`ProgramArguments` to enable your preferred flags. The plist sets
`ProcessType` to `Interactive`: `Background` would throttle earlyoom's CPU
and I/O exactly when it has to run.

## How it works

Linux earlyoom's "low memory and low swap" rule does not work on macOS.
Measured on a 36 GiB M-series machine with a growing memory hog:

* free + file-backed pages level off near 18 % as soon as the compressor
  starts, and stay there, so a memory threshold can't tell "compressing
  happily" from "about to thrash".
* The compressor stops growing near 53 % of RAM (~19.7 GiB), so
  `kern.memorystatus_level` bottoms out around 36 %; everything after that
  goes to swap.
* macOS adds swap files on demand (1, 2, 3, 4 GiB, ...), so "free swap"
  stays at 15-60 % while the machine thrashes.
* `kern.memorystatus_vm_pressure_level` turns `warn` shortly before
  swapping starts. It did not reach `critical` in testing.

So earlyoom acts on any one of:

* swap use growing by `--swap-grow` MiB (default 1024, SIGKILL at 2048)
  while the kernel reports memory pressure. Growth is counted from the
  last time pressure was normal, because pages stay in swap long after the
  memory they were evicted for is free again.
* critical kernel memory pressure (SIGTERM; `--no-pressure` turns it off).
* available memory (free + file-backed + purgeable pages, as a share of
  that plus anonymous and compressor pages, or `kern.memorystatus_level` if
  lower) below `-m`, and free swap below `-s` (default 100 %, i.e. no swap
  condition).

Other details:

* Swap comes from the `vm.swapusage` sysctl.
* Processes are enumerated via `libproc` (`proc_pidinfo`/`KERN_PROCARGS2`).
* macOS has no `oom_score`; the victim is the process with the largest
  physical footprint (`proc_pid_rusage`), adjusted by `--prefer`/`--avoid`.
  Unlike RSS, the footprint includes compressed and swapped-out pages.

## Differences vs. Linux earlyoom

* No `oom_score` / `oom_score_adj` — physical footprint ranking only.
* `--kernel-oom` does not exist (no sysrq-trigger).
* `mlockall()` is not implemented on macOS; there is no way to lock the
  daemon into RAM.
* Notifications use `osascript` instead of D-Bus.
* `kernel_task` (pid 0) and `launchd` (pid 1) are never killed.
* Without root, processes owned by other users can't be inspected or
  signaled and are skipped automatically.

## Caveats

* Without `--avoid`, the largest process may be something you don't want
  to lose (WindowServer logs you out when killed).
* SIP-protected processes can't be killed even as root; that's fine, they
  just show up as kill failures in the log.

## License

MIT, same as [earlyoom](https://github.com/rfjakob/earlyoom). This is an
independent re-implementation for macOS.
