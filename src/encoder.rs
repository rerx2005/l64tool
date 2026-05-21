use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use walkdir::WalkDir;

use crate::cipher::{Target, detect_bytecode_format, encode_l64};
use crate::luau_compile;
use crate::luajit_compile;

pub struct EncoderOpts {
    pub compile_code: bool,
    pub preserve_symbols: bool,
    pub verbose: bool,
    pub target: Target,
    pub overwrite: bool,
}

fn output_path(src: &Path) -> PathBuf {
    src.with_extension("l64")
}

fn warn_bytecode_mismatch(data: &[u8], target: Target, path: &Path) {
    if let Some(detected) = detect_bytecode_format(data) {
        let expected = if target.is_luajit() { "luajit" } else { "luau" };
        if detected != expected {
            eprintln!(
                "warning: {} appears to contain {detected} bytecode, but target is {target} (expects {expected})",
                path.display()
            );
        }
    } else {
        eprintln!(
            "warning: {} does not appear to be valid Lua bytecode — encoding anyway (l64 is just a cipher)",
            path.display()
        );
    }
}

fn process_file(
    path: &Path,
    out_path: Option<&Path>,
    opts: &EncoderOpts,
) -> Result<()> {
    let raw = fs::read(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let bytecode = if opts.compile_code {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("input");

        if opts.verbose {
            eprintln!("compiling {} for target {}...", path.display(), opts.target);
        }

        if opts.target.is_luajit() {
            luajit_compile::compile_luajit(&raw, name, opts.preserve_symbols)
                .with_context(|| format!("LuaJIT compilation failed for {}", path.display()))?
        } else {
            luau_compile::compile_luau(&raw, opts.preserve_symbols)
                .with_context(|| format!("Luau compilation failed for {}", path.display()))?
        }
    } else {
        warn_bytecode_mismatch(&raw, opts.target, path);
        raw
    };

    let encoded = encode_l64(&bytecode, opts.target)
        .with_context(|| format!("encoding failed for {}", path.display()))?;

    let out = out_path
        .map(PathBuf::from)
        .unwrap_or_else(|| output_path(path));

    if out.exists() && !opts.overwrite {
        bail!(
            "{} already exists (use -O/--overwrite to replace)",
            out.display()
        );
    }

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&out, &encoded)
        .with_context(|| format!("failed to write {}", out.display()))?;

    if opts.verbose {
        eprintln!(
            "{} -> {} (encoded for {})",
            path.display(),
            out.display(),
            opts.target
        );
    } else {
        println!("{} -> {}", path.display(), out.display());
    }

    Ok(())
}

pub fn encode_file(path: &Path, output: Option<&Path>, opts: &EncoderOpts) -> Result<()> {
    process_file(path, output, opts)
}

pub fn encode_dir_with_depth(
    dir: &Path,
    recursive: bool,
    opts: &EncoderOpts,
) -> Result<()> {
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }

    let walker = if recursive {
        WalkDir::new(dir)
    } else {
        WalkDir::new(dir).max_depth(1)
    };

    let mut count = 0u64;
    let mut errors = 0u64;

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let matches = path.is_file()
            && path.extension().is_some_and(|e| {
                let e = e.to_string_lossy().to_lowercase();
                e == "lua" || e == "luac"
            });

        if matches {
            match process_file(path, None, opts) {
                Ok(()) => count += 1,
                Err(e) => {
                    eprintln!("error: {e:#}");
                    errors += 1;
                }
            }
        }
    }

    println!("\nEncoded {count} file(s), {errors} error(s).");
    Ok(())
}

pub fn encode_batch(files: &[PathBuf], opts: &EncoderOpts) -> Result<()> {
    let mut errors = 0u64;

    for path in files {
        if let Err(e) = process_file(path, None, opts) {
            eprintln!("error: {e:#}");
            errors += 1;
        }
    }

    if errors > 0 {
        eprintln!("\n{errors} error(s) during batch encoding.");
    }

    Ok(())
}
