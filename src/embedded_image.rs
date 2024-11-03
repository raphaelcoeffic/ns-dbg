use std::{fs, path::Path};

use anyhow::Result;
use image_builder::progress_bar;
use liblzma::read::XzDecoder;
use tar::Archive;

pub fn install_base_image<P>(dest: P) -> Result<()>
where
    P: AsRef<Path>,
{
    let base_image = include_bytes!("../base.tar.xz");
    let bar = progress_bar(base_image.len() as u64);
    let decoder = XzDecoder::new(bar.wrap_read(base_image.as_slice()));

    let dest = dest.as_ref();
    fs::create_dir_all(dest).unwrap();

    log::info!("unpacking base image into {}", dest.display());
    Ok(Archive::new(decoder).unpack(dest)?)
}
