use std::{
    ffi::OsString,
    fmt::Debug,
    fs::{create_dir_all, read_link},
    io,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{exit, Command},
};

use anyhow::{Context, Result};
use clap::Parser;
use namespaces::enter_namespaces_as_root;
use overlay::OverlayMount;
use pid_lookup::pid_lookup;
use procfs::process::Process;
use rustix::{
    path::Arg,
    process::geteuid,
    thread::{unshare, UnshareFlags},
};

mod namespaces;
mod overlay;
mod pid_lookup;

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

fn make_overlay_dirs() -> Result<(PathBuf, PathBuf, PathBuf)> {
    let overlay_dir = get_overlay_dir();
    let upper_dir = overlay_dir.join("upper");
    let work_dir = overlay_dir.join("work");

    create_dir_all(&upper_dir)
        .and(create_dir_all(&work_dir))
        .context("could not create state directory")?;

    Ok((overlay_dir, upper_dir, work_dir))
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

fn main() -> Result<()> {
    let args = Args::parse();
    init_logging();

    let lead_pid = if let Ok(pid) = args.container_id.parse::<i32>() {
        pid
    } else if let Some(pid) = pid_lookup(&args.container_id) {
        pid
    } else {
        log::error!("could not find container PID");
        exit(exitcode::NOINPUT);
    };
    log::debug!("container PID: {}", lead_pid);

    let img_dir = get_img_dir(&args);
    if !img_dir.exists() || !img_dir.join("store").exists() {
        image_builder::install_nix(&img_dir)
            .context("could not install Nix")?;
        image_builder::build_base(&img_dir)
            .context("could not build base image")?;
    }

    let (overlay_dir, upper_dir, work_dir) = make_overlay_dirs()?;

    if !geteuid().is_root() {
        log::debug!("re-executing with sudo...");
        reexec_with_sudo(lead_pid, &img_dir, &overlay_dir)?
    }

    let overlay = match OverlayMount::new(img_dir, upper_dir, work_dir) {
        Err(err) => {
            log::error!("could not create base image mount: {:?}", err);
            exit(exitcode::OSERR);
        }
        Ok(mnt) => {
            log::debug!("detached mount created");
            mnt
        }
    };

    let proc_env = match Process::new(lead_pid).and_then(|p| p.environ()) {
        Err(err) => {
            log::error!("could not fetch the process environment: {err}");
            exit(exitcode::OSERR);
        }
        Ok(env) => env,
    };

    enter_namespaces_as_root(lead_pid)?;

    log::debug!("mounting overlay...");
    unshare(UnshareFlags::NEWNS)
        .context("could not create new mount namespace")?;
    overlay
        .mount("/nix")
        .context("could not mount base image")?;

    // TODO: path HOME w/ user as defined by /etc/passwd

    // TODO: find shell in this order:
    // - zsh
    // - bash
    // - sh at last

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

    cmd.status()?;

    Ok(())
}
