use std::{
    collections::HashMap,
    fmt::Debug,
    fs::{create_dir_all, read_link},
    io,
    os::unix::process::CommandExt,
    path::Path,
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

/// Container debug CLI
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Base image path
    #[arg(short, long, env)]
    img_path: Option<String>,

    /// Container ID
    container_id: String,
}

impl Args {
    fn args(&self, lead_pid: Option<i32>) -> Vec<String> {
        let mut args = vec![];
        if self.img_path.is_some() {
            args.push("--img-path".to_string());
            args.push(self.img_path.clone().unwrap().to_string_lossy().into());
        }
        if let Some(lead_pid) = lead_pid {
            args.push(lead_pid.to_string())
        } else {
            args.push(self.container_id.clone())
        }
        args
    }
}

const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

fn init_logging() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_env("LOGLEVEL")
        .format_timestamp(None)
        .format_target(false)
        .init();
}

fn get_proc_env(pid: i32) -> Result<HashMap<String, String>> {
    Ok(Process::new(pid)?
        .environ()?
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_string_lossy().to_string(),
                v.to_string_lossy().to_string(),
            )
        })
        .collect())
}

fn reexec_with_sudo(args: &Args, lead_pid: i32) -> Result<(), io::Error> {
    let self_exe = read_link("/proc/self/exe")?;
    let loglevel = std::env::var("LOGLEVEL").unwrap_or_default();
    let mut cmd_args = vec![
        String::from("_RUNNING_WITH_SUDO=1"),
        format!("LOGLEVEL={}", loglevel),
        String::from(self_exe.to_str().unwrap()),
    ];
    cmd_args.extend(args.args(Some(lead_pid)));
    Err(Command::new("sudo").args(cmd_args).exec())
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
    log::debug!("lead PID: {}", lead_pid);

    let overlay = match args.img_path.clone() {
        Some(img_path) => {
            let img_path = Path::new(&img_path);
            if !img_path.exists() || !img_path.is_dir() {
                log::error!("image path does not exist or is not a directory");
                exit(exitcode::NOINPUT);
            }
            log::debug!("image path seems valid");

            let upper_dir = Path::new("ofs/upper");
            create_dir_all(upper_dir)?;

            let work_dir = Path::new("ofs/work");
            create_dir_all(work_dir)?;

            if !geteuid().is_root() {
                log::debug!("re-executing with sudo...");
                reexec_with_sudo(&args, lead_pid)?
            }

            match OverlayMount::new(img_path, upper_dir, work_dir) {
                Err(err) => {
                    log::error!("could not create base image mount: {:?}", err);
                    exit(exitcode::OSERR);
                }
                Ok(mnt) => {
                    log::debug!("detached mount created");
                    Some(mnt)
                }
            }
        }
        None => None,
    };

    let mut proc_env = match get_proc_env(lead_pid) {
        Err(err) => {
            // TODO: check the different error types
            log::error!("could not fetch the process environment: {err}");
            exit(exitcode::OSERR);
        }
        Ok(env) => env,
    };

    let default_path = String::from(DEFAULT_PATH);
    let mut proc_path = proc_env
        .get("PATH")
        .filter(|p| !p.is_empty())
        .unwrap_or(&default_path)
        .clone();

    enter_namespaces_as_root(lead_pid)?;

    if let Some(overlay) = overlay {
        log::debug!("mounting overlay...");
        unshare(UnshareFlags::NEWNS)
            .context("could not create new mount namespace")?;

        let nix = Path::new("/nix");
        create_dir_all(nix)?;
        overlay.mount(nix)?;

        // let cache_dir = nix.join(".cache");
        // if !cache_dir.exists() {
        //     create_dir_all(cache_dir)?;
        // }

        // update PATH
        proc_path =
            format!("/nix/.base/sbin:/nix/.base/bin:/nix/.bin:{proc_path}");

        let nix_base = "/nix/.base";
        proc_env.extend(
            [
                (
                    "XDG_DATA_DIR",
                    format!("/usr/local/share:/usr/share:{nix_base}/share"),
                ),
                ("XDG_CACHE_HOME", String::from("/nix/.cache")),
                ("TERMINFO_DIRS", format!("{nix_base}/share/terminfo")),
                ("LIBEXEC_PATH", format!("{nix_base}/libexec")),
                ("INFOPATH", format!("{nix_base}/share/info")),
                ("NIX_CONF_DIR", String::from("/nix/etc")),
            ]
            .map(|(k, v)| (k.into(), v)),
        )
    }

    let term = std::env::var("TERM").unwrap_or_default();
    match std::env::var("_RUNNING_WITH_SUDO") {
        Ok(val) => {
            log::debug!("_RUNNING_WITH_SUDO={val}");
        }
        Err(err) => {
            log::debug!("error: {:?}", err);
        }
    }

    proc_env.extend(
        [("PATH", proc_path), ("TERM", term)].map(|(k, v)| (k.into(), v)),
    );

    // TODO: path HOME w/ user as defined by /etc/passwd

    // TODO: find shell in this order:
    // - zsh
    // - bash
    // - sh at last

    Command::new("zsh").env_clear().envs(proc_env).status()?;

    Ok(())
}
