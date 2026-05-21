#[allow(
    clippy::all,
    non_camel_case_types,
    non_snake_case,
    unused_variables,
    dead_code,
    unused_imports,
    unused_mut,
    unreachable_patterns
)]
pub mod bytecode;
#[allow(
    clippy::all,
    non_camel_case_types,
    non_snake_case,
    unused_variables,
    dead_code,
    unused_imports,
    unused_mut,
    unreachable_patterns
)]
pub mod source;

use bytecode::BytecodeReader;

/// Decompile Luau v3 bytecode into reconstructed source code.
pub fn decompile_v3(data: &[u8]) -> Result<String, String> {
    let mut reader = BytecodeReader::new(data);
    let file = reader.read_bytecode_file()?;
    source::reconstruct(&file)
}
