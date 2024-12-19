use std::{
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{bail, Result};
use clap::Parser;
use tempfile::TempDir;

use dive::image_builder::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Persistent base directory
    #[arg(short, long, env)]
    persistent_base_dir: Option<PathBuf>,

    /// Alternative flake directory
    #[arg(short, long, env)]
    flake_dir: Option<PathBuf>,

    /// Add binary into base image
    #[arg(short = 'b', long = "add-binary")]
    binaries: Vec<PathBuf>,

    /// Architecture
    #[arg(short, long, env)]
    arch: Option<String>,

    /// No packaging
    #[arg(long, env)]
    unpackaged: bool,

    /// Compress base image
    #[arg(short, long, env)]
    uncompressed: bool,

    /// Shell
    #[arg(long)]
    shell_exec: bool,

    /// Output name
    #[arg(short, long, env, default_value = "base")]
    output: String,
}

enum BaseDir {
    Temp(TempDir),
    Persistent(PathBuf),
}

impl BaseDir {
    pub fn new<P: AsRef<Path>>(dir: Option<P>) -> io::Result<Self> {
        if let Some(dir) = dir {
            Self::new_persistent_dir(dir)
        } else {
            Self::new_temp_dir()
        }
    }

    fn new_temp_dir() -> io::Result<Self> {
        TempDir::new().map(Self::Temp)
    }

    fn new_persistent_dir<P>(dir: P) -> io::Result<Self>
    where
        P: AsRef<Path>,
    {
        fs::create_dir_all(dir.as_ref())
            .map(|_| Self::Persistent(dir.as_ref().to_owned()))
    }

    pub fn path(&self) -> &Path {
        match self {
            Self::Temp(tmp) => tmp.path(),
            Self::Persistent(dir) => dir.as_ref(),
        }
    }
}

impl Drop for BaseDir {
    fn drop(&mut self) {
        if let Self::Temp(tmp) = self {
            let _ = chmod(&tmp.path().join("store"), |mode| mode | 0o700);
        }
    }
}

fn is_native_arch(arch: &str) -> bool {
    arch == std::env::consts::ARCH
}

fn is_qemu_supported_arch(arch: &str) -> bool {
    fs::exists(format!("/proc/sys/fs/binfmt_misc/qemu-{arch}")).is_ok_and(|x| x)
}

fn init_logging() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_env("LOGLEVEL")
        .format_timestamp(None)
        .format_target(false)
        .init();
}

fn main() -> Result<()> {
    let args = Args::parse();
    init_logging();

    let base_dir = BaseDir::new(args.persistent_base_dir)?;
    let mut base_builder = BaseImageBuilder::new(base_dir.path());
    base_builder.binaries(args.binaries);

    if !args.unpackaged {
        base_builder.package(args.output, !args.uncompressed);
    }

    if let Some(flake_dir) = args.flake_dir {
        base_builder.flake_dir(flake_dir);
    }

    if args.shell_exec {
        base_builder.shell_exec(true);
    }

    if let Some(arch) = args.arch {
        if !is_native_arch(&arch) && !is_qemu_supported_arch(&arch) {
            bail!(
                "{arch} does not seem to be supported. \
                 Try installing 'qemu-user-static' to enable support."
            )
        }
        base_builder.build_base_with_arch(&arch)
    } else {
        base_builder.build_base()
    }
}
