use std::env::consts::ARCH;
use std::env::set_current_dir;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{exit, Command, Stdio};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use liblzma::read::XzDecoder;
use regex::Regex;
use rustix::fs::{bind_mount, recursive_bind_mount};
use rustix::path::Arg;
use rustix::process::{chroot, getgid, getuid, waitpid, WaitOptions};
use rustix::runtime::{fork, Fork};
use rustix::thread::{unshare, UnshareFlags};
use tar::Archive;
use tempfile::tempdir;

const NIX_VERSION: &str = "2.24.9";

const NIX_CONF: &str = "experimental-features = nix-command flakes
auto-optimise-store = true
sandbox = false
build-users-group =
";

fn nix_installer_url(version: &str) -> String {
    const NIX_BASE_URL: &str = "https://releases.nixos.org/nix";
    format!("{NIX_BASE_URL}/nix-{version}/nix-{version}-{ARCH}-linux.tar.xz")
}

fn write_nix_paths(nix_dir: &Path) -> Result<(), io::Error> {
    let mut nix_paths = String::new();
    for dir in nix_dir.join("store").read_dir()? {
        nix_paths += dir?.path().file_name().unwrap().to_str().unwrap();
        nix_paths += "\n";
    }

    fs::create_dir_all(nix_dir.join(".cache"))?;
    fs::write(nix_dir.join(".cache/nix_paths"), nix_paths)
}

fn progress_bar(len: u64) -> ProgressBar {
    ProgressBar::new(len).with_style(
        ProgressStyle::with_template(
            "[{percent:>2}%] {bar:40.cyan/blue} \
                {decimal_bytes:>7}/{binary_total_bytes:7} \
                @ {decimal_bytes_per_sec:>8}",
        )
        .unwrap()
        .progress_chars("##-"),
    )
}

/// Download and install Nix.
fn download_and_install_nix(
    version: &str,
    url: &str,
    dest: &Path,
) -> Result<()> {
    println!("downloading {url} into {}", dest.display());
    let response = reqwest::blocking::get(url)?;
    let bar = progress_bar(response.content_length().unwrap_or_default());
    let decoder = XzDecoder::new(bar.wrap_read(response));
    let mut ar = Archive::new(decoder);

    let dest_dir = Path::new(dest);
    let store_dir = dest_dir.join("store");
    fs::create_dir_all(&store_dir)?;

    // unpack files
    let tar_prefix = format!("nix-{version}-{ARCH}-linux");
    for file in ar.entries()? {
        let mut f = file?;
        let fpath = f.path()?;

        if let Ok(fpath) = fpath.strip_prefix(&tar_prefix) {
            if fpath.starts_with("store") {
                f.unpack(dest_dir.join(fpath))?;
            }
        }
    }

    // fix permissions
    fn chmod(path: &Path) -> Result<(), io::Error> {
        fn chmod_readonly(path: &Path) -> Result<(), io::Error> {
            let metadata = fs::metadata(path)?;
            let mode = metadata.permissions().mode();
            fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o555))
        }

        let metadata = fs::symlink_metadata(path)?;
        let file_type = metadata.file_type();

        if file_type.is_symlink() {
            return Ok(());
        }

        if file_type.is_file() {
            return chmod_readonly(path);
        }

        if file_type.is_dir() {
            for entry in path.read_dir()? {
                chmod(&entry?.path())?;
            }
            chmod_readonly(path)?;
        }

        Ok(())
    }

    for dir in store_dir.read_dir()? {
        let path = dir?.path();
        chmod(&path)?;
    }

    write_nix_paths(dest)?;
    println!("done");

    Ok(())
}

fn find_nix(store_dir: &Path, version: &str) -> Result<PathBuf> {
    let nix_re =
        Regex::new(&format!("^[a-z0-9]+-nix-{}", regex::escape(version)))
            .unwrap();

    for dir in store_dir.read_dir()? {
        let path = dir?.path();
        let dir = path.file_name().unwrap();
        if nix_re.is_match(dir.to_str().unwrap()) {
            return Ok(path);
        }
    }

    bail!("Nix path not found")
}

/// Install Nix into `dest`
pub fn install_nix<P>(dest: P) -> Result<()>
where
    P: AsRef<Path>,
{
    let dest = dest.as_ref();
    let nix_etc = dest.join("etc");
    let nix_var = dest.join("var/nix");

    fs::create_dir_all(&nix_etc)?;
    fs::create_dir_all(&nix_var)?;
    fs::write(nix_etc.join("nix.conf"), NIX_CONF)?;

    let nix_store = dest.join("store");
    if !nix_store.exists() {
        let nix_url = nix_installer_url(NIX_VERSION);
        download_and_install_nix(NIX_VERSION, &nix_url, dest)?;
    }

    let nix_bin = dest.join(".bin");
    if !nix_bin.exists() {
        let nix_path = Path::new("/").join(find_nix(&nix_store, NIX_VERSION)?);
        symlink(nix_path.join("bin"), nix_bin)?;
    }

    Ok(())
}

fn symlink_base<P: AsRef<Path>>(base_path: P) -> Result<(), io::Error> {
    let base_link = Path::new("/nix/.base");
    let _ = fs::remove_file(base_link);
    symlink(&base_path, base_link)
}

/// Build base Nix Flake
fn build_base_flake<P>(flake_dir: P) -> Result<PathBuf>
where
    P: AsRef<Path>,
{
    let env = [("PATH", "/nix/.bin"), ("NIX_CONF_DIR", "/nix/etc")];

    let flake_dir = flake_dir.as_ref().canonicalize().unwrap();
    let build_output = Command::new("nix")
        .args([
            "build",
            &format!("path:{}", flake_dir.display()),
            "--no-link",
            "--print-out-paths",
        ])
        .envs(env)
        .stderr(Stdio::inherit())
        .output()?;

    if !build_output.status.success() {
        if let Some(exit_code) = build_output.status.code() {
            bail!("nix build failed with {}", exit_code);
        } else {
            bail!("nix build was interrupted by signal");
        }
    }

    let base_path = PathBuf::from(
        build_output
            .stdout
            .trim_ascii()
            .to_string_lossy()
            .to_string(),
    );
    symlink_base(&base_path)?;

    Ok(base_path)
}

fn user_mount_ns() -> Result<()> {
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();

    unshare(UnshareFlags::NEWNS | UnshareFlags::NEWUSER)
        .context("could not create new user and mount namespace")?;

    write_id_map("uid_map", uid)?;
    write_id_map("gid_map", gid)?;

    return Ok(());

    fn write_id_map(id_file: &str, id: u32) -> Result<(), io::Error> {
        let proc_file = Path::new("/proc/self");
        if id_file == "gid_map" {
            fs::write(proc_file.join("setgroups"), "deny")?;
        }
        fs::write(proc_file.join(id_file), format!("{id} {id} 1"))
    }
}

fn bind_mount_all_dir(base_path: &Path, tmp: &Path) -> Result<()> {
    for dir in Path::new("/").read_dir()? {
        let path = dir?.path();
        if path == Path::new("/nix") {
            continue;
        }
        if path.is_symlink() {
            let dst = path.read_link()?;
            let src = tmp.join(path.file_name().unwrap());
            symlink(dst, src)?;
        } else if path.is_dir() {
            let dst = tmp.join(path.file_name().unwrap());
            fs::create_dir(&dst)?;
            recursive_bind_mount(path, dst)?;
        }
    }

    let tmp_nix = tmp.join("nix");
    fs::create_dir(&tmp_nix)?;
    bind_mount(base_path, tmp_nix)?;

    Ok(())
}

pub fn build_base_in_chroot(nix_dir: &Path, tmp: &Path) -> Result<PathBuf> {
    user_mount_ns()?;
    bind_mount_all_dir(nix_dir, tmp)?;

    chroot(tmp)?;
    set_current_dir("/")?;

    let flake_dir = tempdir()?;
    fs::write(
        flake_dir.path().join("flake.nix"),
        include_str!("debug-shell/flake.nix"),
    )?;

    build_base_flake(flake_dir.path())
}

const SUCCESS: i32 = 0;
const BUILD_FAILED: i32 = 1;
const POST_PROCESS_FAILED: i32 = 2;

pub fn build_base_and_then<P, F>(nix_dir: P, func: F) -> Result<()>
where
    P: AsRef<Path>,
    F: FnOnce(PathBuf) -> Result<()>,
{
    let tmp = tempdir()?;
    println!("building base image in {}", tmp.path().display());

    match unsafe { fork()? } {
        Fork::Child(_) => {
            let mut exit_code = BUILD_FAILED;
            let build_status =
                build_base_in_chroot(nix_dir.as_ref(), tmp.path());

            if let Ok(base_path) = build_status {
                exit_code = match func(base_path) {
                    Err(_) => POST_PROCESS_FAILED,
                    Ok(_) => SUCCESS,
                };
            }
            exit(exit_code);
        }
        Fork::Parent(child_pid) => {
            if let Some(status) =
                waitpid(Some(child_pid), WaitOptions::empty())?
            {
                if status.exit_status().is_some_and(|code| code != 0) {
                    bail!("child process failed");
                }
            } else {
                bail!("child process was signaled or otherwise stopped");
            }
        }
    }

    Ok(())
}

pub fn build_base<P>(nix_dir: P) -> Result<()>
where
    P: AsRef<Path>,
{
    build_base_and_then(nix_dir, |_| Ok(()))
}
