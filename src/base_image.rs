use std::{fs, io, path::Path};

use anyhow::{bail, Result};
use liblzma::read::XzDecoder;
use tar::Archive;

use crate::image_builder::*;

#[cfg(feature = "embedded_image")]
use crate::embedded_image;

#[cfg(not(feature = "embedded_image"))]
use crate::image_builder::BaseImageBuilder;

pub fn update_base_image<P>(dest: &Path, image: Option<P>) -> Result<()>
where
    P: AsRef<Path>,
    P: std::fmt::Debug,
{
    let current_sha256 = if fs::exists(dest.join(".base.sha256"))? {
        Some(fs::read(dest.join(".base.sha256"))?.trim_ascii().to_owned())
    } else {
        log::debug!("no current hash");
        None
    };

    let image_sha256 = if let Some(image) = &image {
        Some(
            fs::read(format!("{}.sha256", image.as_ref().display()))?
                .trim_ascii()
                .to_owned(),
        )
    } else {
        #[cfg(feature = "embedded_image")]
        {
            Some(
                crate::embedded_image::base_image_sha256()
                    .as_bytes()
                    .to_owned(),
            )
        }

        #[cfg(not(feature = "embedded_image"))]
        {
            log::debug!("no embedded image");
            None
        }
    };

    if image_sha256.is_none() {
        if current_sha256.is_none() {
            #[cfg(feature = "embedded_image")]
            return embedded_image::install_base_image(dest);

            #[cfg(not(feature = "embedded_image"))]
            return BaseImageBuilder::new(dest).build_base();
        }

        return Ok(());
    }

    if current_sha256.is_some_and(|h| h == image_sha256.unwrap()) {
        log::debug!("SHA256 unchanged");
        return Ok(());
    }

    if let Some(image) = &image {
        install_base_image_from_archive(dest, image.as_ref())
    } else {
        #[cfg(feature = "embedded_image")]
        return embedded_image::install_base_image(dest);

        #[cfg(not(feature = "embedded_image"))]
        unreachable!()
    }
}

fn install_base_image_from_archive(dest: &Path, image: &Path) -> Result<()> {
    if let Ok(f) = fs::File::open(image.with_extension("tar.xz")) {
        let bar = progress_bar(f.metadata()?.len());
        install_base_image_from_reader(dest, XzDecoder::new(bar.wrap_read(f)))
    } else if let Ok(f) = fs::File::open(image.with_extension("tar")) {
        let bar = progress_bar(f.metadata()?.len());
        install_base_image_from_reader(dest, bar.wrap_read(f))
    } else {
        bail!("could not find base image archive");
    }
}

pub fn install_base_image_from_reader<R>(dest: &Path, reader: R) -> Result<()>
where
    R: io::Read,
{
    if dest.exists() {
        // remove previous base image first
        log::info!("removing current base image");
        for dir in dest.read_dir()? {
            let path = dir?.path();
            if let Err(err) = chmod(&path, |mode| mode | 0o700) {
                log::error!(
                    "could not fix permissions for {}: {}",
                    path.display(),
                    err
                );
                bail!(err);
            }
            if path.is_dir() {
                if let Err(err) = fs::remove_dir_all(&path) {
                    log::error!("could not remove {}: {}", path.display(), err);
                    bail!(err);
                }
            } else if let Err(err) = fs::remove_file(&path) {
                log::error!("could not remove {}: {}", path.display(), err);
                bail!(err);
            }
        }
    } else {
        fs::create_dir_all(dest).unwrap();
    }

    log::info!("unpacking base image into {}", dest.display());
    Ok(Archive::new(reader).unpack(dest)?)
}
