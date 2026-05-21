use std::path::PathBuf;

fn main() {
    build_luau_compiler();
}

fn build_luau_compiler() {
    let luau_root = PathBuf::from("vendor/luau");

    let compiler_src = luau_root.join("Compiler/src");
    let ast_src = luau_root.join("Ast/src");
    let common_src = luau_root.join("Common/src");

    let bytecode_src = luau_root.join("Bytecode/src");

    let compiler_inc = luau_root.join("Compiler/include");
    let compiler_src_inc = luau_root.join("Compiler/src");
    let ast_inc = luau_root.join("Ast/include");
    let common_inc = luau_root.join("Common/include");
    let bytecode_inc = luau_root.join("Bytecode/include");

    let compiler_cpp: Vec<PathBuf> = [
        "BuiltinFolding.cpp",
        "Builtins.cpp",
        "Compiler.cpp",
        "ConstantFolding.cpp",
        "CostModel.cpp",
        "TableShape.cpp",
        "Types.cpp",
        "ValueTracking.cpp",
        "lcode.cpp",
    ]
    .iter()
    .map(|f| compiler_src.join(f))
    .collect();

    let ast_cpp: Vec<PathBuf> = [
        "Allocator.cpp",
        "Ast.cpp",
        "Confusables.cpp",
        "Cst.cpp",
        "Lexer.cpp",
        "Location.cpp",
        "Parser.cpp",
        "PrettyPrinter.cpp",
    ]
    .iter()
    .map(|f| ast_src.join(f))
    .collect();

    let common_cpp: Vec<PathBuf> = ["StringUtils.cpp"]
        .iter()
        .map(|f| common_src.join(f))
        .collect();

    let bytecode_cpp: Vec<PathBuf> = ["BytecodeBuilder.cpp"]
        .iter()
        .map(|f| bytecode_src.join(f))
        .collect();

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++17")
        .include(&compiler_inc)
        .include(&compiler_src_inc)
        .include(&ast_inc)
        .include(&common_inc)
        .include(&bytecode_inc)
        .define("NDEBUG", None)
        .define("LUACODE_API", "extern \"C\"")
        .warnings(false);

    for src in compiler_cpp
        .iter()
        .chain(ast_cpp.iter())
        .chain(common_cpp.iter())
        .chain(bytecode_cpp.iter())
    {
        build.file(src);
    }

    build.compile("luau_compiler");

    println!("cargo:rerun-if-changed=vendor/luau/Compiler/src");
    println!("cargo:rerun-if-changed=vendor/luau/Ast/src");
    println!("cargo:rerun-if-changed=vendor/luau/Common/src");
    println!("cargo:rerun-if-changed=vendor/luau/Bytecode/src");
}
