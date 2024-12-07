use std::{
    fs::read_link,
    io,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{exit, Command},
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use procfs::process::Process;
use rustix::{
    process::geteuid,
    runtime::{fork, Fork},
};

use dive::base_image::*;
use dive::namespaces::*;
use dive::pid_lookup::*;
use dive::shared_mount::*;
use dive::shell::*;

const APP_NAME: &str = "dive";
const IMG_DIR: &str = "base-img";

const ENV_IMG_DIR: &str = "_IMG_DIR";
const ENV_STATE_DIR: &str = "_STATE_DIR";
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

fn get_state_dir() -> PathBuf {
    if let Ok(ovl_dir) = std::env::var(ENV_STATE_DIR) {
        return PathBuf::from(ovl_dir);
    }
    dirs::state_dir().unwrap().join(APP_NAME)
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
    state_dir: &Path,
) -> Result<(), io::Error> {
    let self_exe = read_link("/proc/self/exe")?;
    let loglevel = std::env::var("LOGLEVEL").unwrap_or_default();
    Err(Command::new("sudo")
        .arg("_WITH_SUDO=1")
        .args([
            format!("LOGLEVEL={}", loglevel),
            format!("{}={}", ENV_LEAD_PID, lead_pid),
            format!("{}={}", ENV_IMG_DIR, img_dir.display()),
            format!("{}={}", ENV_STATE_DIR, state_dir.display()),
            format!("{}", self_exe.display()),
        ])
        .arg(container_id)
        .exec())
}

fn runs_with_sudo() -> bool {
    std::env::var("_WITH_SUDO").is_ok()
}

fn prepare_shell_environment(
    shared_mount: &SharedMount,
    lead_pid: i32,
) -> Result<()> {
    let detached_mount = match shared_mount.make_detached_mount() {
        Err(err) => {
            bail!("could not make detached mount: {:?}", err);
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

    let state_dir = get_state_dir();
    let mnt_builder = SharedMountBuilder::new(&state_dir, &img_dir)?;

    if !geteuid().is_root() {
        log::debug!("re-executing with sudo...");
        reexec_with_sudo(&args.container_id, lead_pid, &img_dir, &state_dir)?
    }

    let shared_mount = mnt_builder
        .make_mount(lead_pid)
        .context("could not init shared mount")?;

    match unsafe { fork()? } {
        Fork::Child(_) => {
            if let Err(err) = prepare_shell_environment(&shared_mount, lead_pid)
            {
                log::error!("{err}");
                exit(1);
            }

            let proc_env = match Process::new(1).and_then(|p| p.environ()) {
                Err(err) => {
                    log::error!(
                        "could not fetch the process environment: {err}"
                    );
                    exit(1);
                }
                Ok(env) => env,
            };

            let mut shell = Shell::new(&args.container_id);
            shell.env(proc_env);

            match shell.spawn() {
                Err(err) => {
                    log::error!("cannot execute shell: {err}");
                    exit(1);
                }
                Ok(exit_code) => exit(exit_code),
            }
        }
        Fork::Parent(child_pid) => {
            let res = wait_for_child(child_pid)?;
            exit(res);
        }
    }
}
