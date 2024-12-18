pub mod base_image;
pub mod image_builder;
pub mod namespaces;
pub mod nixos;
pub mod nixpkgs;
pub mod overlay;
pub mod pid_lookup;
pub mod shared_mount;
pub mod shell;

#[cfg(feature = "embedded_image")]
mod embedded_image;

mod pid_file;

pub(crate) const CACHE_HOME: &str = "/nix/.cache";
pub(crate) const CONFIG_HOME: &str = "/nix/.config";

pub(crate) const USER_ENV_DIR: &str = "/nix/.env";
pub(crate) const BASE_DIR: &str = "/nix/.base";
pub(crate) const ETC_DIR: &str = "/nix/etc";

pub(crate) const SSL_CERTS: &str = "/nix/.base/etc/ssl/certs/ca-bundle.crt";

pub const BASE_PACKAGES: &[&str] = &[
    "bash",
    "cacert",
    "coreutils",
    "curl",
    "diffutils",
    "dig",
    "findutils",
    "gnugrep",
    "gnused",
    "gnutar",
    "gzip",
    "helix",
    "htop",
    "iproute2",
    "iputils",
    "jq",
    "kitty.terminfo",
    "less",
    "lsof",
    "man",
    "nano",
    "netcat-openbsd",
    "procps",
    "sngrep",
    "sqlite",
    "strace",
    "tcpdump",
    "util-linux",
    "vim",
    "xz",
    "zsh",
    "zsh-prezto",
    "zsh-autosuggestions",
    "zsh-completions",
    "zsh-fast-syntax-highlighting",
];
