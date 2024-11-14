use std::{
    ffi::CString,
    fs::{create_dir_all, remove_file, write, File, OpenOptions},
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use fd_lock::RwLock;
use rustix::{
    fd::{AsRawFd, BorrowedFd},
    fs::{self, bind_mount, fstat, MountPropagationFlags},
    mount::{
        mount_change, move_mount, open_tree, MoveMountFlags, OpenTreeFlags,
    },
    process::{waitpid, WaitOptions},
    thread::{
        move_into_thread_name_spaces, unshare, Pid, RawPid,
        ThreadNameSpaceType, UnshareFlags,
    },
};

use crate::pid_file::PidFile;
use crate::{namespaces::get_userns_uid, overlay::OverlayMount};

pub struct SharedMountBuilder {
    state_dir: PathBuf,
    base_img: PathBuf,
}

impl SharedMountBuilder {
    pub fn new(state_dir: &Path, base_img: &Path) -> Result<Self> {
        // create all directories
        ["rootless", "rootful"]
            .iter()
            .try_for_each(|r| {
                let overlay_dir = state_dir.join(r);
                ["lower", "layers/upper", "layers/work", "merged", "pids"]
                    .iter()
                    // create all sub-directories
                    .try_for_each(|d| create_dir_all(overlay_dir.join(d)))
                    .and_then(|_| {
                        // create lock file if not yet existing
                        OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open(overlay_dir.join("lock"))
                            .map(|_| ())
                    })
            })
            .context("could not create overlay directories")?;

        Ok(SharedMountBuilder {
            state_dir: state_dir.to_owned(),
            base_img: base_img.to_owned(),
        })
    }

    pub fn make_mount(self, lead_pid: i32) -> Result<SharedMount> {
        // check the user namespace's owner UID
        let userns_uid = get_userns_uid(lead_pid).context(
            "could not get owner UID for the container's user namespace",
        )?;

        let (base_dir, id_mapping) = if userns_uid != 0 {
            (self.state_dir.join("rootless"), None)
        } else {
            let base_img_metadata = self.base_img.metadata()?;
            let base_img_uid = base_img_metadata.uid();

            let id_mapping = if base_img_uid != 0 {
                let base_img_gid = base_img_metadata.gid();
                Some(IdMaps {
                    uid_map: IdMap::new(base_img_uid, 0),
                    gid_map: IdMap::new(base_img_gid, 0),
                })
            } else {
                None
            };

            (self.state_dir.join("rootful"), id_mapping)
        };

        let lock_file = base_dir.join("lock");
        let mut flock = RwLock::new(File::open(lock_file)?);
        let _guard = flock.write()?;

        let pids_dir = base_dir.join("pids");
        let merged_dir = base_dir.join("merged");

        if !enter_shared_mount_namespace(&pids_dir)? {
            // create a private mount namespace for the overlay
            private_mount_namespace()
                .context("could not create private mount namespace")?;

            let lower_dir = base_dir.join("lower");
            let layers_dir = base_dir.join("layers");

            if let Some(id_mapping) = id_mapping {
                bind_mount_idmapped(&self.base_img, &lower_dir, &id_mapping)?;
                bind_mount_idmapped(&layers_dir, &layers_dir, &id_mapping)?;
            } else {
                bind_mount(&self.base_img, &lower_dir)?;
            }

            OverlayMount::new(
                &lower_dir,
                layers_dir.join("upper"),
                layers_dir.join("work"),
            )
            .and_then(|ovl| ovl.mount(&merged_dir))
            .context("could not mount base image")?;
        }

        let pid_file =
            PidFile::new(pids_dir).context("failed to create pid file")?;

        let mnt = SharedMount {
            _pid_file: pid_file,
            merged_dir,
        };

        Ok(mnt)
    }
}

pub struct SharedMount {
    _pid_file: PidFile,
    merged_dir: PathBuf,
}

impl SharedMount {
    pub fn make_detached_mount(&self) -> Result<DetachedMount> {
        let mnt_fd = open_tree(
            rustix::fs::CWD,
            &self.merged_dir,
            OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
        )?;

        Ok(DetachedMount { mnt_fd })
    }
}

pub struct DetachedMount {
    mnt_fd: OwnedFd,
}

impl DetachedMount {
    pub fn mount<P>(self, target: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let stat = fstat(self.mnt_fd.as_fd())?;
        if stat.st_uid != 0 || stat.st_gid != 0 {
            log::warn!(
                "id mapped mount needed (uid={}, gid={})",
                stat.st_uid,
                stat.st_gid
            );
        }

        create_dir_all(target.as_ref())?;
        move_mount(
            self.mnt_fd.as_fd(),
            "",
            rustix::fs::CWD,
            target.as_ref(),
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )?;

        Ok(())
    }

    pub fn mount_in_new_namespace<P>(self, target: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        unshare(UnshareFlags::NEWNS)
            .context("could not create new mount namespace")?;

        self.mount(target)
    }
}

fn private_mount_namespace() -> Result<()> {
    unshare(UnshareFlags::NEWNS)?;
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )?;

    Ok(())
}

fn enter_shared_mount_namespace(pids_dir: &Path) -> Result<bool> {
    for entry in pids_dir.read_dir().unwrap() {
        let entry = entry?;
        let pid = entry.file_name();
        match File::open(format!("/proc/{}/ns/mnt", pid.to_string_lossy())) {
            Err(_) => {
                let _ = remove_file(entry.path()).is_ok();
                continue;
            }
            Ok(f) => {
                if move_into_thread_name_spaces(
                    f.as_fd(),
                    ThreadNameSpaceType::MOUNT,
                )
                .is_ok()
                {
                    log::debug!("entered mount namespace");
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

// based on https://github.com/brauner/mount-idmapped
fn bind_mount_idmapped(
    source: &Path,
    target: &Path,
    id_mapping: &IdMaps,
) -> Result<()> {
    log::debug!(
        "id mapped mount {} -> {}",
        source.display(),
        target.display()
    );
    let userns_fd = new_userns_fd(id_mapping)
        .context("cannot create new user namespace")?;

    let lower_fd = open_tree(
        rustix::fs::CWD,
        source,
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )?;

    mount_set_userns(lower_fd.as_fd(), userns_fd.as_fd())
        .context("id mapping lower failed")?;

    move_mount(
        lower_fd.as_fd(),
        "",
        rustix::fs::CWD,
        target,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;

    Ok(())
}

struct IdMaps {
    uid_map: IdMap,
    gid_map: IdMap,
}

fn new_userns_fd(id_mapping: &IdMaps) -> Result<OwnedFd, std::io::Error> {
    let child_pid = clone_new_userns().unwrap();

    // child process
    if child_pid == 0 {
        unsafe {
            libc::exit(libc::kill(libc::getpid(), libc::SIGSTOP));
        };
    }

    let IdMaps { uid_map, gid_map } = id_mapping;
    write_id_map(child_pid, "uid_map", uid_map).unwrap();
    write_id_map(child_pid, "gid_map", gid_map).unwrap();

    let userns_fd = fs::open(
        format!("/proc/{}/ns/user", child_pid),
        fs::OFlags::RDONLY,
        fs::Mode::empty(),
    )
    .unwrap();

    unsafe {
        libc::kill(child_pid, libc::SIGKILL);
    };
    let _ = waitpid(Pid::from_raw(child_pid), WaitOptions::empty());

    Ok(userns_fd)
}

fn clone_new_userns() -> Result<RawPid, std::io::Error> {
    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct clone3_args {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
    }

    let mut args = clone3_args {
        flags: libc::CLONE_NEWUSER as u64,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
    };

    let args_ptr = &mut args as *mut clone3_args;
    let args_size = std::mem::size_of::<clone3_args>();

    let ret = unsafe { libc::syscall(libc::SYS_clone3, args_ptr, args_size) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret as i32)
    }
}

#[derive(Copy, Clone)]
struct IdMap {
    sys_id: u32,
    mapped_id: u32,
}

impl IdMap {
    fn new(sys_id: u32, mapped_id: u32) -> Self {
        IdMap { sys_id, mapped_id }
    }
}

fn write_id_map(
    pid: i32,
    id_file: &str,
    id_map: &IdMap,
) -> Result<(), std::io::Error> {
    let proc_file = PathBuf::from(format!("/proc/{}", pid));
    if id_file == "gid_map" {
        write(proc_file.join("setgroups"), "deny")?;
    }
    let map_line = format!("{} {} 1", id_map.sys_id, id_map.mapped_id);
    write(proc_file.join(id_file), &map_line)
}

fn mount_set_userns(
    mnt_fd: BorrowedFd<'_>,
    userns_fd: BorrowedFd<'_>,
) -> Result<(), std::io::Error> {
    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct mount_attr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }

    const MOUNT_ATTR_IDMAP: u64 = 0x00100000;
    let mut args = mount_attr {
        attr_set: MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns_fd.as_raw_fd() as u64,
    };

    let args_ptr = &mut args as *mut mount_attr;
    let args_size = std::mem::size_of::<mount_attr>();

    let empty_c_str = CString::from(c"");
    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            mnt_fd.as_raw_fd(),
            empty_c_str.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_RECURSIVE,
            args_ptr,
            args_size,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
