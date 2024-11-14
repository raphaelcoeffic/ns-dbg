use std::{
    collections::HashSet,
    ffi::OsString,
    iter::IntoIterator,
    os::fd::{AsFd, AsRawFd},
    path::Path,
    process::exit,
};

use anyhow::{bail, Result};
use procfs::process::{Namespace, Process};
use rustix::{
    fs::{open, Mode, OFlags},
    process::{pidfd_open, Pid, PidfdFlags},
    thread::{
        move_into_thread_name_spaces, set_thread_gid, set_thread_uid, Gid,
        ThreadNameSpaceType, Uid,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NsTuple(OsString, u64, u64);

impl From<(OsString, Namespace)> for NsTuple {
    fn from(value: (OsString, Namespace)) -> Self {
        let (ns_type, ns) = value;
        NsTuple(ns_type, ns.identifier, ns.device_id)
    }
}

fn namespace_type_by_name(ns_type: &OsString) -> ThreadNameSpaceType {
    match ns_type.to_str().unwrap() {
        "cgroup" => ThreadNameSpaceType::CONTROL_GROUP,
        "ipc" => ThreadNameSpaceType::INTER_PROCESS_COMMUNICATION,
        "mnt" => ThreadNameSpaceType::MOUNT,
        "net" => ThreadNameSpaceType::NETWORK,
        "pid" => ThreadNameSpaceType::PROCESS_ID,
        "user" => ThreadNameSpaceType::USER,
        "uts" => ThreadNameSpaceType::HOST_NAME_AND_NIS_DOMAIN_NAME,
        _ => ThreadNameSpaceType::empty(),
    }
}

fn namespace_set(proc: &Process) -> Result<HashSet<NsTuple>> {
    Ok(proc
        .namespaces()?
        .0
        .into_iter()
        .map(|ns| ns.into())
        .collect())
}

pub fn enter_namespaces_as_root(lead_pid: i32) -> Result<()> {
    let lead = Process::new(lead_pid)?;
    let lead_ns = match namespace_set(&lead) {
        Err(err) => {
            bail!("cannot inspect lead process namespaces: {err}");
        }
        Ok(ns) => ns,
    };

    let me = Process::myself()?;
    let my_ns = match namespace_set(&me) {
        Err(err) => {
            bail!("cannot inspect own namespaces: {err}");
        }
        Ok(ns) => ns,
    };

    // Compute the set of namespace we need to enter
    let mut ns_set = ThreadNameSpaceType::empty();
    for ns in lead_ns.difference(&my_ns) {
        ns_set = ns_set.union(namespace_type_by_name(&ns.0));
    }

    if ns_set.is_empty() {
        log::debug!("no point in entering anything: we're already there!");
        return Ok(());
    }

    let lead_pid = Pid::from_raw(lead_pid)
        .expect("lead_pid should be a signed integer > 0");
    let pid_fd = pidfd_open(lead_pid, PidfdFlags::empty())
        .expect("lead_pid cannot be opened");

    if let Err(err) = move_into_thread_name_spaces(pid_fd.as_fd(), ns_set) {
        log::error!("cannot enter namespaces: {}", err);
        exit(exitcode::NOPERM)
    }

    set_thread_uid(Uid::ROOT)?;
    set_thread_gid(Gid::ROOT)?;

    Ok(())
}

// #define NSIO 0xb7
// #define NS_GET_OWNER_UID _IO(NSIO, 0x4)
//
// uid_t uid;
// ioctl(userns_fd, NS_GET_OWNER_UID, &uid);

use libc::uid_t;
use std::os::raw::c_ulong;

const NSIO: u32 = 0xb7;
const NS_GET_OWNER_UID: c_ulong = ioctl_sys::io!(NSIO, 0x4) as c_ulong;

pub fn get_userns_uid(pid: i32) -> Result<u32> {
    let proc_pid = Path::new("/proc").join(pid.to_string());
    if !proc_pid.exists() {
        bail!("process does not exist");
    }

    let userns_file = proc_pid.join("ns/user");
    match open(userns_file, OFlags::RDONLY, Mode::empty()) {
        Err(err) => bail!("cannot open userns: {:?}", err),
        Ok(userns_fd) => {
            let mut uid: uid_t = 0;
            let ret = unsafe {
                ioctl_sys::ioctl(
                    userns_fd.as_raw_fd(),
                    NS_GET_OWNER_UID,
                    &mut uid as *mut uid_t,
                )
            };
            if ret < 0 {
                bail!(
                    "cannot get userns uid: {}",
                    std::io::Error::last_os_error()
                )
            } else {
                Ok(uid as u32)
            }
        }
    }
}
