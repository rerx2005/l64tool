/// Provide `__clear_cache` for aarch64 musl targets where libgcc
/// doesn't include it. LuaJIT's `lj_mcode.c` references this symbol.
#[cfg(all(target_arch = "aarch64", target_env = "musl"))]
#[no_mangle]
pub unsafe extern "C" fn __clear_cache(beg: *mut u8, end: *mut u8) {
    let line: usize = 64;
    let mut p = (beg as usize) & !(line - 1);
    while p < end as usize {
        core::arch::asm!("dc cvau, {}", in(reg) p, options(nostack));
        p += line;
    }
    core::arch::asm!("dsb ish", options(nostack));
    p = (beg as usize) & !(line - 1);
    while p < end as usize {
        core::arch::asm!("ic ivau, {}", in(reg) p, options(nostack));
        p += line;
    }
    core::arch::asm!("dsb ish", "isb", options(nostack));
}
