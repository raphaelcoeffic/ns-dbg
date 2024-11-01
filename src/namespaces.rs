use std::{
    collections::HashSet, ffi::OsString, iter::IntoIterator, os::fd::AsFd,
    process::exit,
};

use anyhow::Result;
use procfs::process::{Namespace, Process};
use rustix::{
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
            log::error!("cannot inspect lead process namespaces: {err}");
            exit(exitcode::OSERR);
        }
        Ok(ns) => ns,
    };
    log::debug!("lead_ns = {:?}", lead_ns);

    let me = Process::myself()?;
    let me_id = me.pid;
    log::debug!("my pid = {}", me_id);

    let my_ns = match namespace_set(&me) {
        Err(err) => {
            log::error!("cannot inspect own namespaces: {err}");
            exit(exitcode::OSERR);
        }
        Ok(ns) => ns,
    };

    // Compute the set of namespace we need to enter
    let mut ns_set = ThreadNameSpaceType::empty();
    for ns in lead_ns.difference(&my_ns) {
        ns_set = ns_set.union(namespace_type_by_name(&ns.0));
    }

    log::debug!("ns_set: {:?}", ns_set);
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
