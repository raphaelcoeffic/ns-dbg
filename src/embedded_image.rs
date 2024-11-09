use std::path::Path;

use anyhow::Result;
use image_builder::progress_bar;
use liblzma::read::XzDecoder;

use crate::base_image::install_base_image_from_reader;

pub fn install_base_image<P>(dest: P) -> Result<()>
where
    P: AsRef<Path>,
{
    let base_image = include_bytes!("../base.tar.xz");
    let bar = progress_bar(base_image.len() as u64);
    let decoder = XzDecoder::new(bar.wrap_read(base_image.as_slice()));

    install_base_image_from_reader(dest.as_ref(), decoder)
}

pub fn base_image_sha256() -> &'static str {
    include_str!("../base.sha256").trim()
}
