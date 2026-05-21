use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use walkdir::WalkDir;

use crate::cipher::{detect_bytecode_format, decode_l64};
use crate::luajit_dump;

pub struct DecoderOpts {
    pub source_code: bool,
    pub verbose: bool,
    pub overwrite: bool,
}

fn output_path(src: &Path) -> PathBuf {
    src.with_extension("lua")
}

fn decompile(bytecode: &[u8], verbose: bool) -> Result<Vec<u8>> {
    match detect_bytecode_format(bytecode) {
        Some("luau") => {
            if verbose {
                eprintln!("  decompiling Luau bytecode...");
            }
            let source = lantern::decompile_bytecode(bytecode, 1);
            Ok(source.into_bytes())
        }
        Some("luajit") => {
            if verbose {
                eprintln!("  disassembling LuaJIT bytecode...");
            }
            let listing = luajit_dump::disassemble_luajit(bytecode)?;
            Ok(listing.into_bytes())
        }
        _ => {
            bail!("Unknown bytecode format — cannot decompile");
        }
    }
}

fn process_file(
    path: &Path,
    out_path: Option<&Path>,
    opts: &DecoderOpts,
) -> Result<()> {
    let raw =
        fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;

    let decoded = decode_l64(&raw)
        .with_context(|| format!("failed to decode {}", path.display()))?;

    let output = if opts.source_code {
        decompile(&decoded, opts.verbose)?
    } else {
        decoded
    };

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

    fs::write(&out, &output)
        .with_context(|| format!("failed to write {}", out.display()))?;

    let mode = if opts.source_code {
        "decompiled"
    } else {
        "decoded"
    };

    if opts.verbose {
        let fmt_name = match detect_bytecode_format(&output) {
            Some(f) => f,
            None => {
                if opts.source_code {
                    "source"
                } else {
                    "unknown"
                }
            }
        };
        eprintln!(
            "{} -> {} ({mode}, {fmt_name})",
            path.display(),
            out.display()
        );
    } else {
        println!("{} -> {} ({mode})", path.display(), out.display());
    }

    Ok(())
}

pub fn decode_file(
    path: &Path,
    output: Option<&Path>,
    opts: &DecoderOpts,
) -> Result<()> {
    process_file(path, output, opts)
}

pub fn decode_dir(dir: &Path, recursive: bool, opts: &DecoderOpts) -> Result<()> {
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
        if path.is_file() && path.extension().is_some_and(|e| e == "l64") {
            match process_file(path, None, opts) {
                Ok(()) => count += 1,
                Err(e) => {
                    eprintln!("error: {e:#}");
                    errors += 1;
                }
            }
        }
    }

    let mode = if opts.source_code {
        "Decompiled"
    } else {
        "Decoded"
    };
    println!("\n{mode} {count} file(s), {errors} error(s).");
    Ok(())
}

pub fn decode_batch(files: &[PathBuf], opts: &DecoderOpts) -> Result<()> {
    let mut errors = 0u64;

    for path in files {
        if let Err(e) = process_file(path, None, opts) {
            eprintln!("error: {e:#}");
            errors += 1;
        }
    }

    if errors > 0 {
        eprintln!("\n{errors} error(s) during batch decoding.");
    }

    Ok(())
}
