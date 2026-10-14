// SPDX-License-Identifier: MIT

//! Memory information for macOS.
//!
//! Replaces earlyoom's /proc/meminfo parsing with:
//!   - hw.memsize            -> total physical memory
//!   - host_statistics64()   -> vm_statistics64 page counters
//!   - vm.swapusage          -> swap total/free
//!
//! "MemAvailable" is approximated using Apple's own definition of
//! AVAILABLE_NON_COMPRESSED_MEMORY = active + inactive + free + speculative
//! pages (see xnu doc/vm/memorystatus_notify.md), i.e. all memory that is
//! currently not compressed. This drops exactly when the VM compressor and
//! swapper start working - the "system grinding" symptom we want to prevent.
//!
//! "AnonPages" (memory that user processes actually hold) is approximated
//! as internal + compressor - purgeable pages. Together with the available
//! figure this gives UserMemTotal, the denominator for the
//! available-memory percentage, matching earlyoom's semantics.

use std::mem::MaybeUninit;

/// All sizes in KiB, percentages in 0.0..=100.0.
#[derive(Debug, Default, Clone, Copy)]
pub struct MemInfo {
    pub mem_total_kib: u64,
    pub mem_available_kib: u64,
    pub swap_total_kib: u64,
    pub swap_free_kib: u64,
    pub anon_pages_kib: u64,
    /// mem_available_kib + anon_pages_kib
    pub user_mem_total_kib: u64,
    /// Pages currently held by the VM compressor.
    pub compressor_kib: u64,
    pub mem_available_percent: f64,
    pub swap_free_percent: f64,
    /// kern.memorystatus_level: the kernel's own "percent of memory free"
    /// figure - the same number jetsam acts on. 100.0 when unreadable, so
    /// it can never trip the trigger by accident.
    pub kernel_level_percent: f64,
}

impl MemInfo {
    /// The more pessimistic of our computed availability and the kernel's
    /// memorystatus level. Our metric counts all uncompressed pages as
    /// available, which stays deceptively high once the compressor is
    /// saturated and swap cannot grow (vm-compressor-space-shortage).
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
    // AVAILABLE_NON_COMPRESSED_MEMORY = active + inactive + free + speculative
    let mem_available = pages(
        u64::from(vm.active_count)
            .saturating_add(u64::from(vm.inactive_count))
            .saturating_add(u64::from(vm.free_count))
            .saturating_add(u64::from(vm.speculative_count)),
    );
    let anon_pages = pages(
        u64::from(vm.internal_page_count)
            .saturating_add(u64::from(vm.compressor_page_count))
            .saturating_sub(u64::from(vm.purgeable_count)),
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

    Ok(MemInfo {
        mem_total_kib: mem_total,
        mem_available_kib: mem_available,
        swap_total_kib: swap_total,
        swap_free_kib: swap_free,
        anon_pages_kib: anon_pages,
        user_mem_total_kib: user_mem_total,
        compressor_kib,
        mem_available_percent,
        swap_free_percent,
        kernel_level_percent,
    })
}
