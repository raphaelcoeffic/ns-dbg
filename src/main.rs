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

mod base_image;
mod namespaces;
mod overlay;
mod pid_file;
mod pid_lookup;
mod shared_mount;

#[cfg(feature = "embedded_image")]
mod embedded_image;

use base_image::*;
use namespaces::*;
use overlay::*;
use pid_lookup::*;
use shared_mount::*;

const APP_NAME: &str = "dive";
const IMG_DIR: &str = "base-img";
const OVL_DIR: &str = "overlay";

const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

const ENV_IMG_DIR: &str = "_IMG_DIR";
const ENV_OVL_DIR: &str = "_OVL_DIR";
const ENV_LEAD_PID: &str = "_LEAD_PID";

/// Container debug CLI
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Base image directory
    #[arg(short, long, env)]
    img_dir: Option<String>,

    /// Base image name
    #[arg(short, long, env)]
    base_img: Option<String>,

    /// Container ID
    container_id: String,
}

fn get_lead_pid(container_id: &str) -> Option<i32> {
    std::env::var(ENV_LEAD_PID)
        .ok()
        .and_then(|pid| pid.parse().ok())
        .or_else(|| pid_lookup(container_id))
}

fn get_img_dir(args: &Args) -> PathBuf {
    if let Ok(img_dir) = std::env::var(ENV_IMG_DIR) {
        return PathBuf::from(img_dir);
    }
    if args.img_dir.is_some() {
        return PathBuf::from(args.img_dir.clone().unwrap());
    }
    dirs::state_dir().unwrap().join(APP_NAME).join(IMG_DIR)
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
    container_id: &str,
    lead_pid: i32,
    img_dir: &Path,
    overlay_dir: &Path,
) -> Result<(), io::Error> {
    let self_exe = read_link("/proc/self/exe")?;
    let loglevel = std::env::var("LOGLEVEL").unwrap_or_default();
    Err(Command::new("sudo")
        .args([
            format!("LOGLEVEL={}", loglevel),
            format!("{}={}", ENV_LEAD_PID, lead_pid),
            format!("{}={}", ENV_IMG_DIR, img_dir.display()),
            format!("{}={}", ENV_OVL_DIR, overlay_dir.display()),
            format!("{}", self_exe.display()),
        ])
        .arg(container_id)
        .exec())
}

fn runs_with_sudo() -> bool {
    std::env::var("SUDO_UID").is_ok()
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

fn exec_shell(container_id: &str) -> Result<()> {
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

    // TODO: these variable except for TERM should be initialized in zshenv
    let nix_bin_path = "/nix/.base/sbin:/nix/.base/bin:/nix/.bin";
    cmd.env("PATH", format!("{nix_bin_path}:{proc_path}"));

    if let Ok(term) = std::env::var("TERM") {
        cmd.env("TERM", term);
    } else {
        cmd.env("TERM", "xterm");
    }

    if let Ok(lang) = std::env::var("LANG") {
        cmd.env("LANG", lang);
    } else {
        cmd.env("LANG", "C.UTF-8");
    }

    let prompt = format!(
        "%F{{cyan}}({container_id}) %F{{blue}}%~ %(?.%F{{green}}.%F{{red}})%#%f "
    );
    cmd.env("PROMPT", &prompt);

    let nix_base = "/nix/.base";
    let data_dir = format!("/usr/local/share:/usr/share:{nix_base}/share");
    cmd.envs([
        ("ZDOTDIR", "/nix/etc"),
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

    let lead_pid = if let Some(pid) = get_lead_pid(&args.container_id) {
        pid
    } else {
        log::error!("could not find container PID");
        exit(exitcode::NOINPUT);
    };
    log::debug!("container PID: {}", lead_pid);

    let img_dir = get_img_dir(&args);
    if !runs_with_sudo() {
        update_base_image(&img_dir, args.base_img)?;
    }

    let overlay_dir = get_overlay_dir();
    let overlay_builder = OverlayBuilder::new(&overlay_dir, &img_dir)?;

    if !geteuid().is_root() {
        log::debug!("re-executing with sudo...");
        reexec_with_sudo(&args.container_id, lead_pid, &img_dir, &overlay_dir)?
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
            if let Err(err) = exec_shell(&args.container_id) {
                log::error!("cannot execute shell: {err}");
                exit(1);
            }
            exit(0);
        }
        Fork::Parent(child_pid) => wait_for_child(child_pid),
    }
}
