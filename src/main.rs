use std::{
    collections::HashMap,
    fs::create_dir_all,
    path::{Path, PathBuf},
    process::{exit, Command},
};

use anyhow::{Context, Result};
use clap::Parser;
use namespaces::enter_namespaces_as_root;
use overlay::OverlayMount;
use procfs::process::Process;
use rustix::{
    path::Arg,
    thread::{capabilities, unshare, CapabilityFlags, UnshareFlags},
};

mod namespaces;
mod overlay;

/// Container debug CLI
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Base image path
    #[arg(short, long, env)]
    img_path: Option<PathBuf>,

    /// Lead PID
    #[arg(value_parser = clap::value_parser!(i32).range(1..))]
    lead_pid: i32,
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

fn main() -> Result<()> {
    let args = Args::parse();
    init_logging();

    let overlay = match args.img_path {
        Some(img_path) => {
            if !img_path.exists() || !img_path.is_dir() {
                log::error!("image path does not exist or is not a directory");
                exit(exitcode::NOINPUT);
            }
            log::debug!("image path seems valid");
            let caps =
                capabilities(None).expect("could not fetch own capabilities");
            if !caps.effective.contains(CapabilityFlags::SYS_ADMIN) {
                log::error!("CAP_SYS_ADMIN required: either use 'sudo' or add the capability to the executable");
                exit(exitcode::OSERR);
            }
            log::debug!("yeah, we have SYS_ADMIN");
            match OverlayMount::new(img_path, "./ofs") {
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

    let mut proc_env = match get_proc_env(args.lead_pid) {
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

    enter_namespaces_as_root(args.lead_pid)?;

    if let Some(overlay) = overlay {
        log::debug!("mounting overlay...");
        unshare(UnshareFlags::NEWNS)
            .context("could not create new mount namespace")?;

        let nix = Path::new("/nix");
        create_dir_all(nix)?;
        overlay.mount(nix)?;

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
                ("TERMINFO_DIRS", format!("{nix_base}/share/terminfo")),
                ("LIBEXEC_PATH", format!("{nix_base}/libexec")),
                ("INFOPATH", format!("{nix_base}/share/info")),
            ]
            .map(|(k, v)| (k.into(), v)),
        )
    }

    let term = std::env::var("TERM").unwrap_or_default();

    proc_env.extend(
        [("PATH", proc_path), ("TERM", term)].map(|(k, v)| (k.into(), v)),
    );

    // TODO: find shell in this order:
    // - zsh
    // - bash
    // - sh at last

    Command::new("sh")
        .env_clear()
        .envs(proc_env)
        .spawn()?
        .wait()?;

    Ok(())
}
