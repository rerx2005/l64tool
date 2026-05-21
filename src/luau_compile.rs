use anyhow::{bail, Result};
use std::ffi::c_char;

#[repr(C)]
#[allow(non_snake_case)]
struct LuaCompileOptions {
    optimizationLevel: i32,
    debugLevel: i32,
    typeInfoLevel: i32,
    coverageLevel: i32,
    vectorLib: *const c_char,
    vectorCtor: *const c_char,
    vectorType: *const c_char,
    mutableGlobals: *const *const c_char,
    userdataTypes: *const *const c_char,
    librariesWithKnownMembers: *const *const c_char,
    libraryMemberTypeCb: *const std::ffi::c_void,
    libraryMemberConstantCb: *const std::ffi::c_void,
    disabledBuiltins: *const *const c_char,
}

extern "C" {
    fn luau_compile(
        source: *const c_char,
        size: usize,
        options: *mut LuaCompileOptions,
        outsize: *mut usize,
    ) -> *mut c_char;
}

pub fn compile_luau(source: &[u8], preserve_symbols: bool) -> Result<Vec<u8>> {
    let debug_level = if preserve_symbols { 2 } else { 1 };

    let mut options = LuaCompileOptions {
        optimizationLevel: 1,
        debugLevel: debug_level,
        typeInfoLevel: 0,
        coverageLevel: 0,
        vectorLib: std::ptr::null(),
        vectorCtor: std::ptr::null(),
        vectorType: std::ptr::null(),
        mutableGlobals: std::ptr::null(),
        userdataTypes: std::ptr::null(),
        librariesWithKnownMembers: std::ptr::null(),
        libraryMemberTypeCb: std::ptr::null(),
        libraryMemberConstantCb: std::ptr::null(),
        disabledBuiltins: std::ptr::null(),
    };

    let mut outsize: usize = 0;

    let result = unsafe {
        luau_compile(
            source.as_ptr() as *const c_char,
            source.len(),
            &mut options,
            &mut outsize,
        )
    };

    if result.is_null() {
        bail!("Luau compilation returned null");
    }

    let bytecode = unsafe { std::slice::from_raw_parts(result as *const u8, outsize).to_vec() };

    unsafe {
        libc_free(result as *mut std::ffi::c_void);
    }

    if bytecode.is_empty() {
        bail!("Luau compilation produced empty output");
    }

    // Luau encodes compilation errors in the bytecode itself.
    // If the first byte is 0, the rest is the error message.
    if bytecode[0] == 0 {
        let msg = String::from_utf8_lossy(&bytecode[1..]);
        bail!("Luau compilation error: {msg}");
    }

    Ok(bytecode)
}

extern "C" {
    #[link_name = "free"]
    fn libc_free(ptr: *mut std::ffi::c_void);
}
