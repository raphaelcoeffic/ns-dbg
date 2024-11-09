use std::{
    fs::{remove_file, File, OpenOptions},
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use fd_lock::RwLock;
use rustix::{
    fs::MountPropagationFlags,
    mount::{
        mount_change, move_mount, open_tree, MoveMountFlags, OpenTreeFlags,
    },
    thread::{
        move_into_thread_name_spaces, unshare, ThreadNameSpaceType,
        UnshareFlags,
    },
};

use crate::overlay::{OverlayBuilder, OverlayMount};
use crate::pid_file::PidFile;

pub struct SharedMount {
    _pid_file: PidFile,
    merged_dir: PathBuf,
}

impl SharedMount {
    pub fn new(
        base_dir: &Path,
        overlay_builder: OverlayBuilder,
    ) -> Result<Self> {
        let mut flock = RwLock::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(base_dir.join("lock"))?,
        );
        let _guard = flock.write()?;

        let mut ns_found = false;
        let pids_dir = &overlay_builder.pids_dir;
        let merged_dir = overlay_builder.merged_dir.clone();

        for entry in pids_dir.read_dir().unwrap() {
            let entry = entry?;
            let pid = entry.file_name();
            log::debug!("checking {:?}", pid);
            match File::open(format!("/proc/{}/ns/mnt", pid.to_string_lossy()))
            {
                Err(err) => {
                    log::debug!("pid file open: {}", err);
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
                        ns_found = true;
                        break;
                    }
                }
            }
        }

        if !ns_found {
            log::debug!("enter new mount namespace");
            unshare(UnshareFlags::NEWNS)
                .context("could not create new mount namespace")?;

            log::debug!("make mounts private");
            mount_change(
                "/",
                MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
            )?;

            log::debug!("mount base in state dir");
            OverlayMount::new(
                overlay_builder.lower_dir,
                overlay_builder.upper_dir,
                overlay_builder.work_dir,
            )
            .and_then(|ovl| ovl.mount(&overlay_builder.merged_dir))
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

    pub fn make_detached_mount(&self) -> Result<DetachedMount> {
        let tree_fd = open_tree(
            rustix::fs::CWD,
            &self.merged_dir,
            OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
        )?;

        Ok(DetachedMount(tree_fd))
    }
}

pub struct DetachedMount(OwnedFd);

impl DetachedMount {
    pub fn mount<P>(self, target: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        move_mount(
            self.0.as_fd(),
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
