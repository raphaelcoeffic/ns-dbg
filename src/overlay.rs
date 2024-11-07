use std::fs::create_dir_all;
use std::path::Path;
use std::{os::fd::OwnedFd, path::PathBuf};

use anyhow::{Context, Result};
use rustix::fd::AsFd;
use rustix::fs;
use rustix::mount::{
    fsconfig_create, fsconfig_set_string, fsmount, fsopen, move_mount,
    FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags,
};

pub struct OverlayMount(OwnedFd);

impl OverlayMount {
    pub fn new<L: Into<PathBuf>, D: AsRef<Path>>(
        lower_dir: L,
        upper_dir: D,
        work_dir: D,
    ) -> Result<Self> {
        let lower_dir = lower_dir.into().canonicalize()?;
        let fsfd = fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC)?;
        fsconfig_set_string(fsfd.as_fd(), "source", "user-data")?;
        fsconfig_set_string(fsfd.as_fd(), "lowerdir", lower_dir)?;
        fsconfig_set_string(fsfd.as_fd(), "upperdir", upper_dir.as_ref())?;
        fsconfig_set_string(fsfd.as_fd(), "workdir", work_dir.as_ref())?;
        fsconfig_create(fsfd.as_fd())?;

        let fd_mnt = fsmount(
            fsfd.as_fd(),
            FsMountFlags::FSMOUNT_CLOEXEC,
            MountAttrFlags::empty(),
        )?;
        Ok(OverlayMount(fd_mnt))
    }

    pub fn mount<P>(self, dest: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let dest = dest.as_ref();
        create_dir_all(dest)?;
        move_mount(
            self.0.as_fd(),
            "",
            fs::CWD,
            dest,
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )?;
        Ok(())
    }
}

pub struct OverlayBuilder {
    pub lower_dir: PathBuf,
    pub merged_dir: PathBuf,
    pub upper_dir: PathBuf,
    pub work_dir: PathBuf,
    pub pids_dir: PathBuf,
}

impl OverlayBuilder {
    pub fn new<P, Q>(base_dir: P, lower_dir: Q) -> Result<Self>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        let base_dir = base_dir.as_ref();
        let lower_dir = lower_dir.as_ref().to_owned();

        let merged_dir = base_dir.join("merged");
        let upper_dir = base_dir.join("upper");
        let work_dir = base_dir.join("work");
        let pids_dir = base_dir.join("pids");

        create_dir_all(&merged_dir)
            .and(create_dir_all(&upper_dir))
            .and(create_dir_all(&work_dir))
            .and(create_dir_all(&pids_dir))
            .context("could not create overlay directories")?;

        Ok(OverlayBuilder {
            lower_dir,
            merged_dir,
            upper_dir,
            work_dir,
            pids_dir,
        })
    }
}
