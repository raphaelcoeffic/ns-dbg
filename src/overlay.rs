use std::path::Path;
use std::{fs::create_dir_all, os::fd::OwnedFd, path::PathBuf};

use anyhow::Result;
use rustix::fd::AsFd;
use rustix::fs;
use rustix::mount::{
    fsconfig_create, fsconfig_set_string, fsmount, fsopen, move_mount,
    FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags,
};

pub struct OverlayMount(OwnedFd);

fn make_rel_path<P: AsRef<Path>>(base: P, subdir: &str) -> Result<PathBuf> {
    let mut sub = PathBuf::from(base.as_ref());
    sub.push(subdir);
    create_dir_all(&sub)?;
    Ok(sub)
}

impl OverlayMount {
    pub fn new<L: Into<PathBuf>, D: AsRef<Path>>(
        lower_dir: L,
        data_dir: D,
    ) -> Result<Self> {
        let lower_dir = lower_dir.into().canonicalize()?.into_os_string();
        let data_dir = data_dir.as_ref();

        let upper_dir = make_rel_path(data_dir, "upper")?;
        let work_dir = make_rel_path(data_dir, "work")?;

        let fsfd = fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC)?;
        fsconfig_set_string(fsfd.as_fd(), "source", "nsdb")?;
        fsconfig_set_string(fsfd.as_fd(), "lowerdir", lower_dir)?;
        fsconfig_set_string(
            fsfd.as_fd(),
            "upperdir",
            upper_dir.into_os_string(),
        )?;
        fsconfig_set_string(fsfd.as_fd(), "workdir", work_dir)?;
        fsconfig_create(fsfd.as_fd())?;

        let fd_mnt = fsmount(
            fsfd.as_fd(),
            FsMountFlags::FSMOUNT_CLOEXEC,
            MountAttrFlags::empty(),
        )?;
        Ok(OverlayMount(fd_mnt))
    }

    pub fn mount(self, dest: impl AsRef<Path>) -> Result<()> {
        Ok(move_mount(
            self.0.as_fd(),
            "",
            fs::CWD,
            dest.as_ref(),
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )?)
    }
}
