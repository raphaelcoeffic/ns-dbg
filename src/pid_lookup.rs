#![allow(dead_code)]
use std::{ffi::OsStr, process::Command};

use serde::Deserialize;
use which::which;

struct ContainerRuntime {
    name: &'static str,
    available: fn() -> bool,
    get_pid: fn(&str) -> Option<i32>,
}

fn get_pid_cmd<I, S>(
    cmd: S,
    args: I,
    f: fn(&[u8]) -> Option<i32>,
) -> Option<i32>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(cmd);
    cmd.args(args);

    let output = cmd.output();
    match output {
        Err(_) => {
            log::error!("command '{:?}' failed", cmd);
        }
        Ok(output) => {
            if output.status.success() {
                return f(&output.stdout);
            } else {
                log::debug!(
                    "{:?} {:?}",
                    cmd.get_program(),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    };

    None
}

#[derive(Deserialize, Debug)]
struct PockerdState {
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "Pid")]
    pid: i32,
}

fn pockerd_extract_pid(output: &[u8]) -> Option<i32> {
    let state: PockerdState = serde_json::from_slice(output).unwrap();
    if state.running && state.pid > 0 {
        return Some(state.pid);
    }
    None
}

fn pockerd_get_pid(cmd: &str, name: &str) -> Option<i32> {
    get_pid_cmd(
        cmd,
        ["inspect", "-f", "{{json .State}}", name],
        pockerd_extract_pid,
    )
}

fn nspawn_get_pid(name: &str) -> Option<i32> {
    get_pid_cmd(
        "machinectl",
        ["show", "-p", "Leader", "--value", name],
        |output| {
            if let Ok(str) = std::str::from_utf8(output) {
                if let Ok(pid) = str.parse::<i32>() {
                    return Some(pid);
                }
            }
            None
        },
    )
}

macro_rules! pockerd_rt {
    ($r:expr) => {
        ContainerRuntime {
            name: $r,
            available: || which($r).is_ok(),
            get_pid: |name| pockerd_get_pid($r, name),
        }
    };
}

const _RUNTIMES: &[ContainerRuntime] = &[
    pockerd_rt!("docker"),
    pockerd_rt!("nerdctl"),
    pockerd_rt!("podman"),
    ContainerRuntime {
        name: "systemd-nspawn",
        available: || which("machinectl").is_ok(),
        get_pid: nspawn_get_pid,
    },
];

pub fn pid_lookup(value: &str) -> Option<i32> {
    if let Ok(pid) = value.parse::<i32>() {
        return Some(pid);
    };
    return _RUNTIMES
        .iter()
        .filter(|r| (r.available)())
        .find_map(|r| (r.get_pid)(value));
}
