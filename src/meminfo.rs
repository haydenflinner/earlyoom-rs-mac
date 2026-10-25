// SPDX-License-Identifier: MIT

//! Memory information for macOS.
//!
//! Replaces earlyoom's /proc/meminfo parsing with:
//!   - hw.memsize            -> total physical memory
//!   - host_statistics64()   -> vm_statistics64 page counters
//!   - vm.swapusage          -> swap total/free
//!   - kern.memorystatus_vm_pressure_level -> the kernel's pressure verdict
//!
//! "MemAvailable" is approximated like Linux's: memory that can be had
//! without compressing or swapping anything, i.e. free + file-backed
//! (external, which includes speculative) + purgeable pages.
//!
//! "AnonPages" (memory that user processes actually hold) is approximated
//! as internal - purgeable + compressor pages. The two are disjoint, and
//! together give UserMemTotal, the denominator for the available-memory
//! percentage, matching earlyoom's semantics. (Counting active + inactive
//! as available, as Apple's AVAILABLE_NON_COMPRESSED_MEMORY does, counts
//! every resident anonymous page twice and never drops below ~50%.)

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU64, Ordering};

/// Lowest swap use seen in the current pressure episode (reset to the
/// current value whenever pressure is normal).
static SWAP_BASELINE_KIB: AtomicU64 = AtomicU64::new(0);

/// All sizes in KiB, percentages in 0.0..=100.0.
#[derive(Debug, Default, Clone, Copy)]
pub struct MemInfo {
    pub mem_total_kib: u64,
    pub mem_available_kib: u64,
    pub swap_total_kib: u64,
    pub swap_used_kib: u64,
    /// How much swap use grew since memory pressure was last normal. Unlike
    /// swap_used_kib this drops back to zero: swapped pages linger long
    /// after the memory they were evicted for is free again.
    pub swap_grown_kib: u64,
    pub anon_pages_kib: u64,
    /// mem_available_kib + anon_pages_kib
    pub user_mem_total_kib: u64,
    /// Pages currently held by the VM compressor.
    pub compressor_kib: u64,
    pub mem_available_percent: f64,
    pub swap_free_percent: f64,
    /// kern.memorystatus_level: the kernel's own "percent of memory free"
    /// figure - the same number jetsam acts on. 100.0 when unreadable, so
    /// it can never trip the trigger by accident. It only counts pages the
    /// compressor holds as used, so it stays high until the compressor
    /// fills RAM.
    pub kernel_level_percent: f64,
    /// kern.memorystatus_vm_pressure_level: PRESSURE_NORMAL, _WARN or
    /// _CRITICAL. NORMAL when unreadable.
    pub pressure_level: i32,
}

pub const PRESSURE_NORMAL: i32 = 1;
pub const PRESSURE_WARN: i32 = 2;
pub const PRESSURE_CRITICAL: i32 = 4;

pub fn pressure_name(level: i32) -> &'static str {
    match level {
        PRESSURE_NORMAL => "normal",
        PRESSURE_WARN => "warn",
        PRESSURE_CRITICAL => "critical",
        _ => "?",
    }
}

impl MemInfo {
    /// The more pessimistic of our computed availability and the kernel's
    /// memorystatus level.
    pub fn effective_mem_percent(&self) -> f64 {
        self.mem_available_percent.min(self.kernel_level_percent)
    }
}

fn sysctl_i32(name: &std::ffi::CStr) -> Result<i32, std::io::Error> {
    let mut val: i32 = 0;
    let mut len = std::mem::size_of::<i32>();
    let res = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            &mut val as *mut i32 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(val)
}

fn sysctl_u64(name: &std::ffi::CStr) -> Result<u64, std::io::Error> {
    let mut val: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    let res = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            &mut val as *mut u64 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(val)
}

fn swap_usage() -> Result<(u64, u64), std::io::Error> {
    let mut usage: libc::xsw_usage = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut len = std::mem::size_of::<libc::xsw_usage>();
    let res = unsafe {
        libc::sysctlbyname(
            c"vm.swapusage".as_ptr(),
            &mut usage as *mut libc::xsw_usage as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((usage.xsu_total, usage.xsu_avail))
}

fn vm_stats() -> Result<libc::vm_statistics64, std::io::Error> {
    let mut stats: libc::vm_statistics64 = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    let kr = unsafe {
        libc::host_statistics64(
            mach2::mach_init::mach_host_self(),
            libc::HOST_VM_INFO64,
            &mut stats as *mut libc::vm_statistics64 as *mut libc::integer_t,
            &mut count,
        )
    };
    if kr != libc::KERN_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(kr));
    }
    Ok(stats)
}

fn page_size() -> u64 {
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ps <= 0 {
        // arm64 macOS uses 16 KiB pages, Intel used 4 KiB.
        16384
    } else {
        ps as u64
    }
}

/// Read current memory and swap statistics.
/// Like the C version, this either returns valid data or is a fatal error
/// for the caller.
pub fn parse_meminfo() -> Result<MemInfo, std::io::Error> {
    let page_kib = page_size() / 1024;

    let mem_total = sysctl_u64(c"hw.memsize")? / 1024;
    let (swap_total, swap_free) = match swap_usage() {
        Ok((t, f)) => (t / 1024, f / 1024),
        Err(_) => (0, 0), // swap may be disabled entirely
    };
    let vm = vm_stats()?;

    let pages = |n: u64| n.saturating_mul(page_kib);
    // free_count excludes speculative pages; external_page_count includes
    // them (active + inactive + speculative == external + internal).
    let mem_available = pages(
        u64::from(vm.free_count)
            .saturating_add(u64::from(vm.external_page_count))
            .saturating_add(u64::from(vm.purgeable_count)),
    )
    .min(mem_total);
    let anon_pages = pages(
        u64::from(vm.internal_page_count)
            .saturating_sub(u64::from(vm.purgeable_count))
            .saturating_add(u64::from(vm.compressor_page_count)),
    );
    let user_mem_total = mem_available + anon_pages;
    let compressor_kib = pages(u64::from(vm.compressor_page_count));

    let mem_available_percent = if user_mem_total > 0 {
        mem_available as f64 * 100.0 / user_mem_total as f64
    } else {
        0.0
    };
    let swap_free_percent = if swap_total > 0 {
        swap_free as f64 * 100.0 / swap_total as f64
    } else {
        0.0
    };
    // Higher = healthier, same as mem_available_percent. Absent or
    // out-of-range values degrade to "no opinion".
    let kernel_level_percent = match sysctl_i32(c"kern.memorystatus_level") {
        Ok(level) if (0..=100).contains(&level) => level as f64,
        _ => 100.0,
    };
    let pressure_level = match sysctl_i32(c"kern.memorystatus_vm_pressure_level") {
        Ok(level @ (PRESSURE_WARN | PRESSURE_CRITICAL)) => level,
        _ => PRESSURE_NORMAL,
    };

    let swap_used = swap_total.saturating_sub(swap_free);
    let baseline = if pressure_level == PRESSURE_NORMAL {
        swap_used
    } else {
        SWAP_BASELINE_KIB.load(Ordering::Relaxed).min(swap_used)
    };
    SWAP_BASELINE_KIB.store(baseline, Ordering::Relaxed);

    Ok(MemInfo {
        mem_total_kib: mem_total,
        mem_available_kib: mem_available,
        swap_total_kib: swap_total,
        swap_used_kib: swap_used,
        swap_grown_kib: swap_used - baseline,
        anon_pages_kib: anon_pages,
        user_mem_total_kib: user_mem_total,
        compressor_kib,
        mem_available_percent,
        swap_free_percent,
        kernel_level_percent,
        pressure_level,
    })
}
