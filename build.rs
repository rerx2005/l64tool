use std::path::PathBuf;

fn main() {
    build_luau_compiler();
    build_cache_shim();
}

fn build_cache_shim() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("aarch64") && target.contains("musl") {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let shim_path = PathBuf::from(&out_dir).join("clear_cache_shim.c");
        std::fs::write(
            &shim_path,
            r#"
#if defined(__aarch64__)
void __clear_cache(char *beg, char *end) {
    const long line = 64;
    char *p;
    for (p = (char *)((long)beg & ~(line - 1)); p < end; p += line)
        __asm__ volatile("dc cvau, %0" :: "r"(p) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    for (p = (char *)((long)beg & ~(line - 1)); p < end; p += line)
        __asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
    __asm__ volatile("dsb ish\nisb" ::: "memory");
}
#endif
"#,
        )
        .expect("failed to write cache shim");

        cc::Build::new()
            .file(&shim_path)
            .warnings(false)
            .compile("clear_cache_shim");
    }
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
