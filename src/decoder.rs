use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use walkdir::WalkDir;

use crate::cipher::{detect_bytecode_format, decode_l64};
use crate::luajit_dump;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSourceCode {
    Luajit,
    Luau,
}

impl std::str::FromStr for TargetSourceCode {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "luajit" => Ok(TargetSourceCode::Luajit),
            "luau" => Ok(TargetSourceCode::Luau),
            _ => Err(format!("unknown target '{}' (expected: luajit, luau)", s)),
        }
    }
}

pub struct DecoderOpts {
    pub source_code: bool,
    pub verbose: bool,
    pub overwrite: bool,
    pub target_source_code: Option<TargetSourceCode>,
}

fn output_path(src: &Path) -> PathBuf {
    src.with_extension("lua")
}

fn decompile(
    bytecode: &[u8],
    verbose: bool,
    target_override: Option<TargetSourceCode>,
) -> Result<Vec<u8>> {
    let detected = detect_bytecode_format(bytecode);
    let language = match target_override {
        Some(TargetSourceCode::Luau) => "luau",
        Some(TargetSourceCode::Luajit) => "luajit",
        None => match &detected {
            Some(info) => info.language(),
            None => bail!("Unknown bytecode format — cannot decompile. Use -t to specify."),
        },
    };

    if verbose {
        if let Some(ref info) = detected {
            eprintln!("  detected bytecode: {info}");
        }
    }

    match language {
        "luau" => {
            if let Some(crate::cipher::BytecodeInfo::Luau { version }) = &detected {
                if *version < 6 {
                    eprintln!(
                        "  warning: Luau bytecode v{version} detected — lantern only supports v6. Decompilation may fail or produce errors."
                    );
                }
            }
            if verbose {
                eprintln!("  decompiling Luau bytecode...");
            }
            let source = lantern::decompile_bytecode(bytecode, 1);
            Ok(source.into_bytes())
        }
        "luajit" => {
            if verbose {
                eprintln!("  disassembling LuaJIT bytecode...");
            }
            let listing = luajit_dump::disassemble_luajit(bytecode)?;
            Ok(listing.into_bytes())
        }
        _ => bail!("Unknown bytecode format — cannot decompile"),
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
        decompile(&decoded, opts.verbose, opts.target_source_code)?
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
            Some(info) => info.to_string(),
            None => {
                if opts.source_code {
                    "source".to_string()
                } else {
                    "unknown".to_string()
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
