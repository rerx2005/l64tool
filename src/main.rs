mod cipher;
mod decoder;
mod encoder;
mod luajit_compile;
mod luajit_dump;
mod luau_compile;

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

use cipher::Target;
use decoder::DecoderOpts;
use encoder::EncoderOpts;

/// Farming Simulator .l64 encoder/decoder — compile, encrypt, decrypt,
/// and decompile Luau / LuaJIT scripts.
#[derive(Parser, Debug)]
#[command(name = "l64tool", version, about)]
struct Cli {
    /// Show third-party licenses
    #[arg(short = 'l', long = "licenses")]
    licenses: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Encode Lua source or bytecode into encrypted .l64 files
    Encoder(EncoderArgs),
    /// Decode encrypted .l64 files into bytecode or Lua source
    Decoder(DecoderArgs),
}

// ── Encoder ─────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
struct EncoderArgs {
    /// Encode a single file
    #[arg(short = 'f', long = "file")]
    file: Option<PathBuf>,

    /// Encode all files in a directory
    #[arg(short = 'd', long = "dir")]
    dir: Option<PathBuf>,

    /// Encode multiple files (space-separated)
    #[arg(short = 'b', long = "batch", num_args = 1..)]
    batch: Option<Vec<PathBuf>>,

    /// Recurse into subdirectories (with --dir)
    #[arg(short = 'r', long = "recursive")]
    recursive: bool,

    /// Output path (single file only)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

    /// Compile source code to bytecode before encoding
    /// (without this flag, input is expected to already be bytecode)
    #[arg(short = 'c', long = "compile-code")]
    compile_code: bool,

    /// Preserve debug symbols (variable names, line info)
    #[arg(short = 'p', long = "preserve-symbols")]
    preserve_symbols: bool,

    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Target game version
    #[arg(short = 't', long = "target", value_parser = parse_target)]
    target: Target,

    /// Overwrite existing output files
    #[arg(short = 'O', long = "overwrite")]
    overwrite: bool,
}

fn parse_target(s: &str) -> std::result::Result<Target, String> {
    s.parse()
}

// ── Decoder ─────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
struct DecoderArgs {
    /// Decode a single .l64 file
    #[arg(short = 'f', long = "file")]
    file: Option<PathBuf>,

    /// Decode all .l64 files in a directory
    #[arg(short = 'd', long = "dir")]
    dir: Option<PathBuf>,

    /// Decode multiple .l64 files (space-separated)
    #[arg(short = 'b', long = "batch", num_args = 1..)]
    batch: Option<Vec<PathBuf>>,

    /// Recurse into subdirectories (with --dir)
    #[arg(short = 'r', long = "recursive")]
    recursive: bool,

    /// Output path
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

    /// Decompile bytecode to readable Lua source code
    /// (without this flag, output is raw bytecode)
    #[arg(short = 's', long = "source-code")]
    source_code: bool,

    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Overwrite existing output files
    #[arg(short = 'O', long = "overwrite")]
    overwrite: bool,
}

// ── Licenses ────────────────────────────────────────────────────────

fn print_licenses() {
    println!(
        r#"l64tool — Third-Party Licenses
==============================

Luau (luau-lang/luau)
  License: MIT
  https://github.com/luau-lang/luau/blob/master/LICENSE.txt

LuaJIT (LuaJIT/LuaJIT)
  License: MIT
  https://luajit.org/luajit.html

Lantern (Paint-a-Farm/lantern)
  License: MIT
  https://github.com/Paint-a-Farm/lantern

clap
  License: MIT / Apache 2.0
  https://github.com/clap-rs/clap

anyhow
  License: MIT / Apache 2.0
  https://github.com/dtolnay/anyhow

walkdir
  License: MIT / Unlicense
  https://github.com/BurntSushi/walkdir

mlua
  License: MIT
  https://github.com/mlua-rs/mlua
"#
    );
}

// ── Main ────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.licenses {
        print_licenses();
        return Ok(());
    }

    let Some(command) = cli.command else {
        bail!("No command specified. Use 'encoder' or 'decoder'. See --help.");
    };

    match command {
        Command::Encoder(args) => run_encoder(args),
        Command::Decoder(args) => run_decoder(args),
    }
}

fn run_encoder(args: EncoderArgs) -> Result<()> {
    let has_input = args.file.is_some() || args.dir.is_some() || args.batch.is_some();
    if !has_input {
        bail!("No input specified. Use -f, -d, or -b to provide files.");
    }

    if args.output.is_some() && (args.dir.is_some() || args.batch.is_some()) {
        bail!("-o/--output is only available for single file mode (-f).");
    }

    let opts = EncoderOpts {
        compile_code: args.compile_code,
        preserve_symbols: args.preserve_symbols,
        verbose: args.verbose,
        target: args.target,
        overwrite: args.overwrite,
    };

    if let Some(ref path) = args.file {
        encoder::encode_file(path, args.output.as_deref(), &opts)?;
    }

    if let Some(ref dir) = args.dir {
        encoder::encode_dir_with_depth(dir, args.recursive, &opts)?;
    }

    if let Some(ref files) = args.batch {
        encoder::encode_batch(files, &opts)?;
    }

    Ok(())
}

fn run_decoder(args: DecoderArgs) -> Result<()> {
    let has_input = args.file.is_some() || args.dir.is_some() || args.batch.is_some();
    if !has_input {
        bail!("No input specified. Use -f, -d, or -b to provide .l64 files.");
    }

    let opts = DecoderOpts {
        source_code: args.source_code,
        verbose: args.verbose,
        overwrite: args.overwrite,
    };

    if let Some(ref path) = args.file {
        decoder::decode_file(path, args.output.as_deref(), &opts)?;
    }

    if let Some(ref dir) = args.dir {
        decoder::decode_dir(dir, args.recursive, &opts)?;
    }

    if let Some(ref files) = args.batch {
        decoder::decode_batch(files, &opts)?;
    }

    Ok(())
}
