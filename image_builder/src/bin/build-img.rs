use anyhow::{bail, Result};
use rustix::path::Arg;
use std::{collections::HashSet, fs, io, path::Path, process::Command};

use image_builder::*;

fn read_nix_paths<P>(nix_dir: P) -> Result<HashSet<String>, io::Error>
where
    P: AsRef<Path>,
{
    Ok(fs::read(nix_dir.as_ref().join(".cache/nix_paths"))?
        .to_string_lossy()
        .lines()
        .map(|l| l.to_owned())
        .collect())
}

fn read_nix_closure<P>(path: P) -> Result<HashSet<String>>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    let output = Command::new("nix-store")
        .args(["-qR", path.as_str()?])
        .env("PATH", "/nix/.bin")
        .env("NIX_CONF_DIR", "/nix/etc")
        .output()?;

    Ok(output
        .stdout
        .to_string_lossy()
        .lines()
        .map(|p| p.rsplit('/').next().unwrap().to_owned())
        .collect())
}

fn package_base_image<P, Q>(base_path: P, output: Q) -> Result<()>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let base_set = read_nix_closure(&base_path)?;
    let nix_set = read_nix_paths("/nix")?;

    let tar_status = Command::new("tar")
        .args([
            "--directory=/nix",
            "--exclude=var/nix/*",
            "-c",
            "-f",
            &format!("{}", output.as_ref().display()),
            "-I",
            "xz -T0",
            ".bin",
            ".base",
            "etc",
            "var/nix",
        ])
        .args(nix_set.union(&base_set).map(|p| "store/".to_owned() + p))
        .env("PATH", "/nix/.base/bin")
        .status()?;

    if !tar_status.success() {
        if let Some(exit_code) = tar_status.code() {
            bail!("tar failed with {}", exit_code);
        } else {
            bail!("tar was interrupted by signal");
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let nix_dir = Path::new("nix");
    install_nix(nix_dir)?;

    let output = std::env::current_dir()?.join("base.tar.xz");
    build_base_and_then(nix_dir, |p| package_base_image(p, output))
}
