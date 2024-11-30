use std::{
    collections::HashSet,
    env::{consts::ARCH, set_current_dir},
    fs, io,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    process::{exit, Command, Stdio},
};

use anyhow::{bail, Context, Result};
use include_dir::{include_dir, Dir};
use indicatif::{ProgressBar, ProgressStyle};
use liblzma::read::XzDecoder;
use regex::Regex;
use rustix::{
    fs::{bind_mount, recursive_bind_mount, unmount, UnmountFlags},
    path::Arg,
    process::{chroot, getgid, getuid, waitpid, WaitOptions},
    runtime::{fork, Fork},
    thread::{unshare, Pid, UnshareFlags},
};
use sha2::{Digest, Sha256};
use tar::Archive;
use tempfile::tempdir;

use crate::shell::*;

const NIX_VERSION: &str = "2.25.2";

const NIX_CONF: &str = "experimental-features = nix-command flakes
extra-nix-path = nixpkgs=flake:nixpkgs
build-users-group =
sandbox = false
";

static FLAKE_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/src/debug-shell");

// Break compilation if 'flake.nix' does not exist
static _FLAKE_NIX_GUARD_: &str = include_str!("debug-shell/flake.nix");

static BASE_SHA256: &str = "/nix/.base.sha256";
static BASE_PATHS: &str = "/nix/.base.paths";

static STATIC_FILES: &[(&str, &str)] =
    &[("/nix/etc/.zshrc", include_str!("etc/zshrc"))];

pub struct BaseImageBuilder {
    nix_dir: PathBuf,
    flake_dir: Option<PathBuf>,
    shell_exec: bool,
    package_output: Option<PathBuf>,
    compress: bool,
}

impl BaseImageBuilder {
    const SUCCESS: i32 = 0;
    const BUILD_FAILED: i32 = 1;
    const POST_PROCESS_FAILED: i32 = 2;

    pub fn new<P>(nix_dir: P) -> Self
    where
        P: AsRef<Path>,
    {
        BaseImageBuilder {
            nix_dir: nix_dir.as_ref().to_owned(),
            flake_dir: None,
            shell_exec: false,
            package_output: None,
            compress: false,
        }
    }

    pub fn flake_dir<P>(&mut self, flake_dir: P) -> &mut Self
    where
        P: AsRef<Path>,
    {
        self.flake_dir.replace(flake_dir.as_ref().to_owned());
        self
    }

    pub fn shell_exec(&mut self, shell_exec: bool) -> &mut Self {
        self.shell_exec = shell_exec;
        self
    }

    pub fn package<P>(&mut self, output: P, compress: bool) -> &mut Self
    where
        P: AsRef<Path>,
    {
        self.package_output.replace(PathBuf::from(output.as_ref()));
        self.compress = compress;
        self
    }

    pub fn build_base(&self) -> Result<()> {
        self.build_base_with_arch(ARCH)
    }

    pub fn build_base_with_arch(&self, arch: &str) -> Result<()> {
        install_nix(arch, &self.nix_dir).context("could not install Nix")?;
        log::info!("building base image");

        let tmp = tempdir()?;
        match unsafe { fork()? } {
            Fork::Child(_) => exit(self.build_base_child(tmp.path())),
            Fork::Parent(child_pid) => self.build_base_parent(child_pid),
        }
    }

    fn build_base_child(&self, tmp: &Path) -> i32 {
        let build_status = self.build_base_in_chroot(tmp);

        if build_status.is_err() {
            return Self::BUILD_FAILED;
        }
        let base_path = build_status.unwrap();

        // hash & copy static files (zshrc, etc)
        let mut hasher = Sha256::new();
        hasher.update(base_path.as_os_str().as_encoded_bytes());
        hasher.update(NIX_CONF);

        if let Err(err) = STATIC_FILES.iter().try_for_each(|(dest, content)| {
            hasher.update(content);
            fs::write(dest, content)
        }) {
            log::error!("failed to copy static files: {err}");
            return Self::POST_PROCESS_FAILED;
        }

        let hash = hasher.finalize();
        if let Err(err) = fs::write(BASE_SHA256, format!("{:x}\n", hash)) {
            log::error!("failed to write hash file: {err}");
            return Self::POST_PROCESS_FAILED;
        }

        let gcroots = Path::new("/nix/var/nix/gcroots");
        let gcroots_nix = gcroots.join("nix");
        let gcroots_base = gcroots.join("base");

        if let Err(err) =
            dump_nix_closures([&gcroots_nix, &gcroots_base], BASE_PATHS)
        {
            log::error!("failed to write store paths: {err}");
            return Self::POST_PROCESS_FAILED;
        }

        if let Err(err) = dump_store_db(BASE_PATHS, "/nix/.base.reginfo") {
            log::error!("failed to write base store database: {err}");
            return Self::POST_PROCESS_FAILED;
        }

        if self.shell_exec {
            let shell = Shell::new("build-shell");
            let _ = shell.spawn();
            return Self::SUCCESS;
        }

        if self.do_package().is_err() {
            return Self::POST_PROCESS_FAILED;
        }

        Self::SUCCESS
    }

    fn build_base_parent(&self, child_pid: Pid) -> Result<()> {
        if let Some(status) = waitpid(Some(child_pid), WaitOptions::empty())? {
            if status.exit_status().is_some_and(|code| code != 0) {
                bail!("child process failed");
            }
        } else {
            bail!("child process was signaled or otherwise stopped");
        }

        Ok(())
    }

    fn build_base_in_chroot(&self, tmp: &Path) -> Result<PathBuf> {
        log::debug!("building base in chroot");
        user_mount_ns()?;
        bind_mount_all_dir(&self.nix_dir, tmp)?;

        log::debug!("chroot to {:?}", tmp);
        let current_dir = std::env::current_dir()?;
        chroot(tmp)?;

        log::debug!("set current dir to {:?}", current_dir);
        set_current_dir(current_dir).unwrap();

        // import initial DB
        log::debug!("import initial DB");
        load_nix_reginfo("/nix/.reginfo")?;

        // build_builtins()
        match &self.flake_dir {
            None => {
                let flake_tmp = tempdir()?;
                let flake_dir = flake_tmp.path();

                let flake_nix = FLAKE_DIR.get_file("flake.nix");
                if let Some(flake_nix) = flake_nix {
                    fs::write(
                        flake_dir.join("flake.nix"),
                        flake_nix.contents(),
                    )?;
                }

                let flake_lock = FLAKE_DIR.get_file("flake.lock");
                if let Some(flake_lock) = flake_lock {
                    fs::write(
                        flake_dir.join("flake.lock"),
                        flake_lock.contents(),
                    )?;
                }

                build_base_flake(flake_dir)
            }
            Some(flake_dir) => build_base_flake(flake_dir),
        }
    }

    fn do_package(&self) -> Result<()> {
        if self.package_output.is_none() {
            // no packaging, run garbage collection instead
            log::info!("running nix garbage collector");
            return run_nix_gc();
        }

        let output = self.package_output.as_ref().unwrap();
        let archive_suffix = if self.compress { "tar.xz" } else { "tar" };
        let archive_name = format!("{}.{}", output.display(), archive_suffix);

        if self.compress {
            log::info!(
                "packaging and compressing base image to {}",
                archive_name,
            );
        } else {
            log::info!("packaging base image to {}", archive_name);
        }

        // temporary nix db mount
        let tmp_db_dir = tempdir()?;
        bind_mount(tmp_db_dir.path(), "/nix/var/nix/db")
            .context("failed to mount temporary DB directory")?;
        load_nix_reginfo("/nix/.base.reginfo")?;

        let mut tar_cmd = Command::new("tar");

        // prefer native tar over emulated one
        let current_path = std::env::var_os("PATH")
            .filter(|path| !path.is_empty())
            .map(|path| path.to_string_lossy().into_owned() + ":")
            .unwrap_or_default();

        let path_env = format!("{current_path}/nix/.base/bin");
        tar_cmd.env("PATH", path_env);

        tar_cmd.args(["--directory=/nix", "-c", "-f", &archive_name]);

        if self.compress {
            tar_cmd.args(["-I", "xz -T0"]);
        }

        // file list
        tar_cmd.args([
            ".bin",
            ".base",
            ".base.paths",
            ".base.sha256",
            ".base.reginfo",
            "etc",
            "var/nix/db",
            "var/nix/gcroots/nix",
            "var/nix/gcroots/base",
        ]);
        tar_cmd.args(
            read_paths_set(BASE_PATHS)?
                .iter()
                .map(|p| p.strip_prefix("/nix/").unwrap()),
        );

        let tar_status = tar_cmd.status()?;

        if !tar_status.success() {
            if let Some(exit_code) = tar_status.code() {
                bail!("tar failed with {}", exit_code);
            } else {
                bail!("tar was interrupted by signal");
            }
        }

        // remove temporary nix db mount
        unmount("/nix/var/nix/db", UnmountFlags::empty())
            .context("could not unmount nix db")?;
        drop(tmp_db_dir);

        let sha256_name = format!("{}.sha256", output.display());
        fs::copy(BASE_SHA256, sha256_name)
            .context("could not copy hash file")?;

        Ok(())
    }
}

fn nix_installer_url(version: &str, arch: &str) -> String {
    const NIX_BASE_URL: &str = "https://releases.nixos.org/nix";
    format!("{NIX_BASE_URL}/nix-{version}/nix-{version}-{arch}-linux.tar.xz")
}

fn read_paths_set<P>(paths_file: P) -> Result<HashSet<String>, io::Error>
where
    P: AsRef<Path>,
{
    Ok(fs::read_to_string(paths_file.as_ref())?
        .lines()
        .map(|l| l.to_owned())
        .collect())
}

fn dump_nix_closures<I, P, Q>(paths: I, paths_file: Q) -> Result<()>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    // same as "nix path-info -r [path]"
    let mut cmd = Command::new("nix-store");
    cmd.arg("-qR");

    for path in paths.into_iter() {
        cmd.arg(path.as_ref().as_os_str());
    }

    let status = cmd
        .env("PATH", "/nix/.bin")
        .env("NIX_CONF_DIR", "/nix/etc")
        .stdout(fs::File::create(paths_file.as_ref())?)
        .status()?;

    if !status.success() {
        if let Some(exit_code) = status.code() {
            bail!("'nix-store -qR' failed with {}", exit_code);
        } else {
            bail!("'nix-store -qR' was interrupted by signal");
        }
    }

    Ok(())
}

fn dump_store_db<P, Q>(paths_file: P, dest: Q) -> Result<()>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let mut cmd = Command::new("nix-store");

    cmd.arg("--dump-db");
    cmd.args(fs::read_to_string(paths_file.as_ref())?.lines());

    let status = cmd
        .env("PATH", "/nix/.bin")
        .env("NIX_CONF_DIR", "/nix/etc")
        .stdout(fs::File::create(dest.as_ref())?)
        .status()?;

    if !status.success() {
        if let Some(exit_code) = status.code() {
            bail!("'nix-store --dump-db' failed with {}", exit_code);
        } else {
            bail!("'nix-store --dump-db' was interrupted by signal");
        }
    }

    Ok(())
}

fn chmod_apply(path: &Path, func: fn(u32) -> u32) -> Result<(), io::Error> {
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    let new_mode = func(mode);

    if new_mode != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(new_mode))
    } else {
        Ok(())
    }
}

// fix permissions recursively
pub fn chmod(path: &Path, func: fn(u32) -> u32) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    let file_type = metadata.file_type();

    if file_type.is_symlink() {
        return Ok(());
    }

    if file_type.is_file() {
        return chmod_apply(path, func);
    }

    if file_type.is_dir() {
        for entry in path.read_dir()? {
            chmod(&entry?.path(), func)?;
        }
        chmod_apply(path, func)?;
    }

    Ok(())
}

pub fn chmod_dirs(path: &Path, func: fn(u32) -> u32) -> Result<(), io::Error> {
    if fs::symlink_metadata(path)?.file_type().is_dir() {
        for entry in path.read_dir()? {
            chmod_dirs(&entry?.path(), func)?;
        }
        chmod_apply(path, func)?;
    }

    Ok(())
}

pub fn progress_bar(len: u64) -> ProgressBar {
    ProgressBar::new(len).with_style(
        ProgressStyle::with_template(
            "[{percent:>2}%] {bar:40.cyan/blue} \
                {decimal_bytes:>7}/{binary_total_bytes:7} \
                @ {decimal_bytes_per_sec:>8}",
        )
        .unwrap()
        .progress_chars("##-"),
    )
}

/// Download and install Nix.
fn download_and_install_nix(
    version: &str,
    arch: &str,
    url: &str,
    dest: &Path,
) -> Result<()> {
    log::info!("downloading {url} into {}", dest.display());
    let response = ureq::get(url).call()?;
    let content_length: u64 = response
        .header("Content-Length")
        .unwrap_or("")
        .parse()
        .unwrap_or_default();

    let bar = progress_bar(content_length);
    let decoder = XzDecoder::new(bar.wrap_read(response.into_reader()));
    let mut ar = Archive::new(decoder);

    let dest_dir = Path::new(dest);
    let store_dir = dest_dir.join("store");
    fs::create_dir_all(&store_dir)?;

    // unpack files
    let tar_prefix = format!("nix-{version}-{arch}-linux");
    let reginfo = Path::new(".reginfo");
    for file in ar.entries()? {
        let mut f = file?;
        let fpath = f.path()?;

        if let Ok(fpath) = fpath.strip_prefix(&tar_prefix) {
            if fpath.starts_with("store") || fpath == reginfo {
                f.unpack(dest_dir.join(fpath))?;
            }
        }
    }

    for dir in store_dir.read_dir()? {
        let path = dir?.path();
        chmod(&path, |mode| mode & 0o555)?;
    }

    Ok(())
}

fn find_nix(store_dir: &Path, version: &str) -> Result<PathBuf> {
    let nix_re =
        Regex::new(&format!("^[a-z0-9]+-nix-{}", regex::escape(version)))
            .unwrap();

    for dir in store_dir.read_dir()? {
        let path = dir?.path();
        let dir = path.file_name().unwrap();
        if nix_re.is_match(dir.to_str().unwrap()) {
            return Ok(PathBuf::from(dir));
        }
    }

    bail!("Nix path not found")
}

/// Install Nix into `dest`
fn install_nix<P>(arch: &str, dest: P) -> Result<()>
where
    P: AsRef<Path>,
{
    let dest = dest.as_ref();
    let nix_etc = dest.join("etc");
    let nix_var = dest.join("var/nix");

    fs::create_dir_all(&nix_etc)?;
    fs::create_dir_all(&nix_var)?;
    fs::write(nix_etc.join("nix.conf"), NIX_CONF)?;

    let nix_store = dest.join("store");
    if !nix_store.exists() {
        log::info!("installing Nix in {}", dest.display());
        let nix_url = nix_installer_url(NIX_VERSION, arch);
        download_and_install_nix(NIX_VERSION, arch, &nix_url, dest)?;
    }

    let nix_bin = dest.join(".bin");
    let gcroots = dest.join("var/nix/gcroots");
    fs::create_dir_all(&gcroots)?;

    if !symlink_exists(&nix_bin) {
        let nix_store_path = find_nix(&nix_store, NIX_VERSION)?;
        let nix_path = Path::new("/nix/store").join(nix_store_path);
        symlink(nix_path.join("bin"), nix_bin).unwrap();
        symlink(&nix_path, gcroots.join("nix")).unwrap();
    }

    Ok(())
}

fn symlink_exists<P: AsRef<Path>>(path: P) -> bool {
    fs::symlink_metadata(path).is_ok_and(|f| f.file_type().is_symlink())
}

fn symlink_base<P: AsRef<Path>>(base_path: P) -> Result<(), io::Error> {
    let base_link = Path::new("/nix/.base");
    let gcroots = Path::new("/nix/var/nix/gcroots");
    let gcroots_base = gcroots.join("base");
    fs::create_dir_all(gcroots)?;

    let _ = fs::remove_file(base_link);
    symlink(&base_path, base_link)?;

    let _ = fs::remove_file(&gcroots_base);
    symlink(&base_path, &gcroots_base)
}

fn load_nix_reginfo<P: AsRef<Path>>(db_dump: P) -> Result<()> {
    let env = [
        ("PATH", "/nix/.bin"),
        ("NIX_CONF_DIR", "/nix/etc"),
        ("XDG_CACHE_HOME", "/nix/.cache"),
        ("XDG_CONFIG_HOME", "/nix/.config"),
    ];

    let reginfo = fs::File::open(db_dump.as_ref())?;
    let status = Command::new("nix-store")
        .arg("--load-db")
        .envs(env)
        .stdin(reginfo)
        .status()?;

    if !status.success() {
        if let Some(exit_code) = status.code() {
            bail!("'nix-store --load-db' failed with {}", exit_code);
        } else {
            bail!("'nix-store --load-db' was interrupted by signal");
        }
    }

    Ok(())
}

fn run_nix_gc() -> Result<()> {
    let env = [
        ("PATH", "/nix/.bin"),
        ("NIX_CONF_DIR", "/nix/etc"),
        ("XDG_CACHE_HOME", "/nix/.cache"),
        ("XDG_CONFIG_HOME", "/nix/.config"),
    ];

    let status = Command::new("nix")
        .args(["store", "gc"])
        .envs(env)
        .stdout(Stdio::null())
        .status()?;

    if !status.success() {
        if let Some(exit_code) = status.code() {
            bail!("'nix store gc' failed with {}", exit_code);
        } else {
            bail!("'nix store gc' was interrupted by signal");
        }
    }

    Ok(())
}

/// Build base Nix Flake
fn build_base_flake<P>(flake_dir: P) -> Result<PathBuf>
where
    P: AsRef<Path>,
{
    let env = [
        ("PATH", "/nix/.bin"),
        ("NIX_CONF_DIR", "/nix/etc"),
        ("XDG_CACHE_HOME", "/nix/.cache"),
        ("XDG_CONFIG_HOME", "/nix/.config"),
    ];

    let flake_dir = flake_dir.as_ref().canonicalize().unwrap();
    let build_output = Command::new("nix")
        .args([
            "build",
            &format!("path:{}", flake_dir.display()),
            "--no-link",
            "--print-out-paths",
        ])
        .envs(env)
        .stderr(Stdio::inherit())
        .output()?;

    if !build_output.status.success() {
        if let Some(exit_code) = build_output.status.code() {
            bail!("nix build failed with {}", exit_code);
        } else {
            bail!("nix build was interrupted by signal");
        }
    }

    let base_path = PathBuf::from(
        build_output
            .stdout
            .trim_ascii()
            .to_string_lossy()
            .to_string(),
    );
    symlink_base(&base_path)?;

    Ok(base_path)
}

fn user_mount_ns() -> Result<()> {
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();

    if uid != 0 {
        log::debug!("unshare user and mount namespace");
        unshare(UnshareFlags::NEWNS | UnshareFlags::NEWUSER)
            .context("could not create new user and mount namespace")?;

        log::debug!("write UID/GID map");
        write_id_map("uid_map", uid)?;
        write_id_map("gid_map", gid)?;
    } else {
        log::debug!("unshare mount namespace");
        unshare(UnshareFlags::NEWNS)
            .context("could not create new mount namespace")?;
    }

    return Ok(());

    fn write_id_map(id_file: &str, id: u32) -> Result<(), io::Error> {
        let proc_file = Path::new("/proc/self");
        if id_file == "gid_map" {
            fs::write(proc_file.join("setgroups"), "deny")?;
        }
        fs::write(proc_file.join(id_file), format!("{id} {id} 1"))
    }
}

fn bind_mount_all_dir(base_path: &Path, tmp: &Path) -> Result<()> {
    log::debug!("bind mount all directories");
    for dir in Path::new("/").read_dir()? {
        let path = dir?.path();
        if path == Path::new("/nix") {
            continue;
        }
        if path.is_symlink() {
            let dst = path.read_link()?;
            let src = tmp.join(path.file_name().unwrap());
            symlink(dst, src)?;
        } else if path.is_dir() {
            let dst = tmp.join(path.file_name().unwrap());
            fs::create_dir(&dst)?;
            recursive_bind_mount(path, dst)?;
        }
    }

    let tmp_nix = tmp.join("nix");
    fs::create_dir(&tmp_nix)?;
    bind_mount(base_path, tmp_nix)?;

    Ok(())
}
