use std::{
    ffi::OsString,
    fs::read_link,
    io,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{self, exit, Command},
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use procfs::process::Process;
use rustix::{
    process::{geteuid, waitpid, WaitOptions},
    runtime::{fork, Fork},
};

mod namespaces;
mod overlay;
mod pid_file;
mod pid_lookup;
mod shared_mount;

use namespaces::*;
use overlay::*;
use pid_lookup::*;
use shared_mount::*;

#[cfg(feature = "embedded_image")]
mod embedded_image;

#[cfg(not(feature = "embedded_image"))]
use image_builder::BaseImageBuilder;

const APP_NAME: &str = "dive";
const IMG_DIR: &str = "base-img";
const OVL_DIR: &str = "overlay";

const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

const ENV_IMG_DIR: &str = "_NSDGB_IMG_DIR";
const ENV_OVL_DIR: &str = "_NSDGB_OVL_DIR";

/// Container debug CLI
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Base image directory
    #[arg(short, long, env)]
    img_dir: Option<String>,

    /// Container ID
    container_id: String,
}

fn get_img_dir(args: &Args) -> PathBuf {
    if let Ok(img_dir) = std::env::var(ENV_IMG_DIR) {
        return PathBuf::from(img_dir);
    }
    if args.img_dir.is_some() {
        return PathBuf::from(args.img_dir.clone().unwrap());
    }
    dirs::state_dir()
        .unwrap()
        .join(APP_NAME)
        .join(IMG_DIR)
        .to_owned()
}

fn get_overlay_dir() -> PathBuf {
    if let Ok(ovl_dir) = std::env::var(ENV_OVL_DIR) {
        return PathBuf::from(ovl_dir);
    }
    dirs::state_dir().unwrap().join(APP_NAME).join(OVL_DIR)
}

fn init_logging() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_env("LOGLEVEL")
        .format_timestamp(None)
        .format_target(false)
        .init();
}

fn reexec_with_sudo(
    lead_pid: i32,
    img_dir: &Path,
    overlay_dir: &Path,
) -> Result<(), io::Error> {
    let self_exe = read_link("/proc/self/exe")?;
    let loglevel = std::env::var("LOGLEVEL").unwrap_or_default();
    Err(Command::new("sudo")
        .args([
            format!("LOGLEVEL={}", loglevel),
            format!("{}={}", ENV_IMG_DIR, img_dir.display()),
            format!("{}={}", ENV_OVL_DIR, overlay_dir.display()),
            format!("{}", self_exe.display()),
        ])
        .arg(lead_pid.to_string())
        .exec())
}

fn prepare_shell_environment(
    shared_mount: &SharedMount,
    lead_pid: i32,
) -> Result<()> {
    let detached_mount = match shared_mount.make_detached_mount() {
        Err(err) => {
            bail!("could not make detached mount: {err}");
        }
        Ok(m) => m,
    };
    if let Err(err) = enter_namespaces_as_root(lead_pid) {
        bail!("cannot enter container namespaces: {err}");
    }
    if let Err(err) = detached_mount.mount_in_new_namespace("/nix") {
        bail!("cannot mount /nix: {err}");
    }
    Ok(())
}

fn exec_shell() -> Result<()> {
    //
    // TODO: path HOME w/ user as defined by /etc/passwd
    //
    // TODO: find shell in this order:
    // - zsh
    // - bash
    // - sh at last

    let proc_env = match Process::new(1).and_then(|p| p.environ()) {
        Err(err) => {
            bail!("could not fetch the process environment: {err}");
        }
        Ok(env) => env,
    };

    let mut cmd = Command::new("zsh");
    cmd.env_clear();
    cmd.envs(&proc_env);

    let proc_path = if let Some(path) = proc_env
        .get(&OsString::from("PATH"))
        .filter(|v| !v.is_empty())
    {
        path.to_string_lossy().into_owned()
    } else {
        DEFAULT_PATH.to_string()
    };

    let nix_bin_path = "/nix/.base/sbin:/nix/.base/bin:/nix/.bin";
    cmd.env("PATH", format!("{nix_bin_path}:{proc_path}"));

    if let Ok(term) = std::env::var("TERM") {
        cmd.env("TERM", term);
    } else {
        cmd.env("TERM", "xterm");
    }

    let nix_base = "/nix/.base";
    let data_dir = format!("/usr/local/share:/usr/share:{nix_base}/share");
    cmd.envs([
        ("NIX_CONF_DIR", "/nix/etc"),
        ("XDG_CACHE_HOME", "/nix/.cache"),
        ("XDG_CONFIG_HOME", "/nix/.config"),
        ("XDG_DATA_DIR", &data_dir),
    ]);

    cmd.envs([
        ("TERMINFO_DIRS", format!("{nix_base}/share/terminfo")),
        ("LIBEXEC_PATH", format!("{nix_base}/libexec")),
        ("INFOPATH", format!("{nix_base}/share/info")),
    ]);

    let err = cmd.exec();
    bail!("cannot exec: {}", err)
}

fn wait_for_child(child_pid: rustix::thread::Pid) -> Result<()> {
    // TODO: propagate return code properly
    log::debug!("parent pid = {}", process::id());
    let _ = waitpid(Some(child_pid), WaitOptions::empty())
        .context("waitpid failed")?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    init_logging();

    let lead_pid = if let Some(pid) = pid_lookup(&args.container_id) {
        pid
    } else {
        log::error!("could not find container PID");
        exit(exitcode::NOINPUT);
    };
    log::debug!("container PID: {}", lead_pid);

    let img_dir = get_img_dir(&args);
    if !img_dir.exists() || !img_dir.join("store").exists() {
        #[cfg(feature = "embedded_image")]
        embedded_image::install_base_image(&img_dir)
            .context("could not unpack base image")?;

        #[cfg(not(feature = "embedded_image"))]
        BaseImageBuilder::new(&img_dir)
            .build_base()
            .context("could not build base image")?;
    }

    let overlay_dir = get_overlay_dir();
    let overlay_builder = OverlayBuilder::new(&overlay_dir, &img_dir)?;

    if !geteuid().is_root() {
        log::debug!("re-executing with sudo...");
        reexec_with_sudo(lead_pid, &img_dir, &overlay_dir)?
    }

    let shared_mount = SharedMount::new(&overlay_dir, overlay_builder)
        .context("could not init shared mount")?;

    match unsafe { fork()? } {
        Fork::Child(_) => {
            if let Err(err) = prepare_shell_environment(&shared_mount, lead_pid)
            {
                log::error!("{err}");
                exit(1);
            }
            // in normal cases, there is no return from exec_shell()
            if let Err(err) = exec_shell() {
                log::error!("cannot execute shell: {err}");
                exit(1);
            }
            exit(0);
        }
        Fork::Parent(child_pid) => wait_for_child(child_pid),
    }
}
