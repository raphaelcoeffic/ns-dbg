use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};
use regex::Regex;
use tempfile::tempdir;

pub(crate) const ENV_VARS: [(&str, &str); 4] = [
    ("PATH", "/nix/.bin"),
    ("NIX_CONF_DIR", "/nix/etc"),
    ("XDG_CACHE_HOME", crate::CACHE_HOME),
    ("XDG_CONFIG_HOME", crate::CONFIG_HOME),
];

pub(crate) fn dump_closures<I, P, Q>(paths: I, paths_file: Q) -> Result<()>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    // same as "nix path-info -r [path]"
    let mut cmd = Command::new("nix-store");
    cmd.args(["--query", "--references"]);

    for path in paths.into_iter() {
        cmd.arg(path.as_ref().as_os_str());
    }

    check_status(
        cmd.envs(ENV_VARS)
            .stdout(fs::File::create(paths_file.as_ref())?),
    )
    .context("could not dump closures")
}

pub(crate) fn dump_store_db<P, Q>(paths_file: P, dest: Q) -> Result<()>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let mut cmd = Command::new("nix-store");
    cmd.arg("--dump-db");
    cmd.args(fs::read_to_string(paths_file.as_ref())?.lines());

    check_status(cmd.envs(ENV_VARS).stdout(fs::File::create(dest.as_ref())?))
        .context("could not dump store db")
}

pub(crate) fn load_store_db<P: AsRef<Path>>(db_dump: P) -> Result<()> {
    let reginfo = fs::File::open(db_dump.as_ref())?;
    let mut cmd = Command::new("nix-store");
    cmd.arg("--load-db");

    check_status(cmd.envs(ENV_VARS).stdin(reginfo))
        .context("could not load store db")
}

/// Generate and build a flake from a list of packages
pub fn build_flake_from_package_list(
    name: &str,
    description: &str,
    packages: &[&str],
) -> Result<PathBuf> {
    let mut packages: Vec<&str> = Vec::from(packages);
    packages.sort();

    let flake_tmp = tempdir()?;
    let flake_dir = flake_tmp.path();

    let flake_template = include_str!("templates/flake.nix");
    let re = Regex::new(r"\{\{\s*(\w+)\s*\}\}").unwrap();

    let package_list = packages.join(" ");
    let flake = re.replace_all(flake_template, |caps: &regex::Captures| {
        match &caps[1] {
            "name" => name,
            "description" => description,
            "packages" => &package_list,
            _ => "",
        }
    });

    fs::write(flake_dir.join("flake.nix"), flake.as_ref())?;
    build_flake(flake_dir)
}

/// Build Nix flake
pub fn build_flake<P>(flake_dir: P) -> Result<PathBuf>
where
    P: AsRef<Path>,
{
    let flake_dir = flake_dir.as_ref().canonicalize().unwrap();
    let build_output = Command::new("nix")
        .args([
            "build",
            "--quiet",
            "--quiet",
            "--no-link",
            "--print-out-paths",
            &format!("path:{}", flake_dir.display()),
        ])
        .envs(ENV_VARS)
        .stderr(Stdio::inherit())
        .output()?;

    if !build_output.status.success() {
        if let Some(exit_code) = build_output.status.code() {
            bail!("nix build failed with {}", exit_code);
        } else {
            bail!("nix build was interrupted by signal");
        }
    }

    Ok(PathBuf::from(
        String::from_utf8_lossy(build_output.stdout.trim_ascii()).as_ref(),
    ))
}

fn check_status(cmd: &mut Command) -> Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        if let Some(exit_code) = status.code() {
            bail!("returned {}", exit_code);
        } else {
            bail!("interrupted by signal");
        }
    }

    Ok(())
}
