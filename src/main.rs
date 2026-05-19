mod decode;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;
use walkdir::WalkDir;

use decode::decode_l64;

/// Farming Simulator .l64 decoder — converts encrypted .l64 bytecode to
/// standard Luau / LuaJIT bytecode (.lua).
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Decode a single .l64 file
    #[arg(short = 'f', long = "file")]
    file: Option<PathBuf>,

    /// Decode all .l64 files in a directory
    #[arg(short = 'd', long = "dir")]
    dir: Option<PathBuf>,

    /// Decode multiple .l64 files (space-separated list)
    #[arg(short = 'b', long = "batch", num_args = 1..)]
    batch: Option<Vec<PathBuf>>,

    /// Recurse into subdirectories (used with --dir)
    #[arg(short = 'r', long = "recursive")]
    recursive: bool,

    /// Overwrite existing output files
    #[arg(short = 'o', long = "overwrite")]
    overwrite: bool,
}

fn output_path(src: &Path) -> PathBuf {
    src.with_extension("lua")
}

fn process_file(path: &Path, overwrite: bool) -> Result<()> {
    let raw = fs::read(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let decoded = decode_l64(&raw)
        .with_context(|| format!("failed to decode {}", path.display()))?;

    let out = output_path(path);

    if out.exists() && !overwrite {
        bail!(
            "{} already exists (use -o/--overwrite to replace)",
            out.display()
        );
    }

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&out, &decoded)
        .with_context(|| format!("failed to write {}", out.display()))?;

    println!("{} -> {}", path.display(), out.display());
    Ok(())
}

fn process_dir(dir: &Path, recursive: bool, overwrite: bool) -> Result<()> {
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
            match process_file(path, overwrite) {
                Ok(()) => count += 1,
                Err(e) => {
                    eprintln!("error: {e:#}");
                    errors += 1;
                }
            }
        }
    }

    println!("\nDecoded {count} file(s), {errors} error(s).");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let has_input = cli.file.is_some() || cli.dir.is_some() || cli.batch.is_some();

    if !has_input {
        bail!("No input specified. Use -f, -d, or -b to provide .l64 files.");
    }

    if let Some(ref path) = cli.file {
        process_file(path, cli.overwrite)?;
    }

    if let Some(ref dir) = cli.dir {
        process_dir(dir, cli.recursive, cli.overwrite)?;
    }

    if let Some(ref files) = cli.batch {
        for path in files {
            if let Err(e) = process_file(path, cli.overwrite) {
                eprintln!("error: {e:#}");
            }
        }
    }

    Ok(())
}
