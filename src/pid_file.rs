use std::{
    fs,
    path::{Path, PathBuf},
    process,
};

use anyhow::Result;

pub struct PidFile {
    path: PathBuf,
}

impl PidFile {
    pub fn new<P>(dir: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let pid = process::id().to_string();
        let path = dir.as_ref().join(&pid);
        std::fs::write(&path, pid)?;
        Ok(PidFile { path })
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        log::debug!("removing {}", self.path.display());
        if let Err(err) = fs::remove_file(&self.path) {
            log::error!("while removing: {}", err);
        }
    }
}
