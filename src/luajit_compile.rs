use anyhow::{bail, Context, Result};
use mlua::prelude::*;

pub fn compile_luajit(source: &[u8], name: &str, preserve_symbols: bool) -> Result<Vec<u8>> {
    let lua = Lua::new();

    let source_str =
        std::str::from_utf8(source).context("LuaJIT source must be valid UTF-8")?;

    let chunk = lua.load(source_str).set_name(name);

    let func: LuaFunction = chunk
        .into_function()
        .map_err(|e| anyhow::anyhow!("LuaJIT compilation error: {e}"))?;

    let strip = !preserve_symbols;
    let bytecode = func.dump(strip);

    if bytecode.len() < 4 {
        bail!("LuaJIT produced invalid bytecode (too short)");
    }

    if bytecode[..3] != [0x1B, 0x4C, 0x4A] {
        bail!("LuaJIT produced invalid bytecode (bad header)");
    }

    Ok(bytecode)
}
