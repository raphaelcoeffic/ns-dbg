use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    os::unix::process::CommandExt,
    process::{self, exit, Command},
};

use anyhow::{bail, Context, Result};
use rustix::{
    process::{waitpid, WaitOptions},
    runtime::{fork, Fork},
};

const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

pub struct Shell {
    name: String,
    env: HashMap<OsString, OsString>,
}

impl Shell {
    pub fn new(name: &str) -> Self {
        Shell {
            name: name.to_owned(),
            env: HashMap::new(),
        }
    }

    pub fn env<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr> + Eq + std::hash::Hash,
        V: AsRef<OsStr>,
    {
        for (ref key, ref val) in vars {
            self.env
                .insert(key.as_ref().to_owned(), val.as_ref().to_owned());
        }
        self
    }

    pub fn exec(self) -> Result<()> {
        //
        // TODO: path HOME w/ user as defined by /etc/passwd
        //
        // TODO: find shell in this order:
        // - zsh
        // - bash
        // - sh at last

        let mut cmd = Command::new("zsh");
        cmd.env_clear();
        cmd.envs(&self.env);

        let proc_path = if let Some(path) = self
            .env
            .get(&OsString::from("PATH"))
            .filter(|v| !v.is_empty())
        {
            path.to_string_lossy().into_owned()
        } else {
            DEFAULT_PATH.to_string()
        };

        // TODO: these variable except for TERM should be initialized in zshenv
        let nix_bin_path = "/nix/.base/sbin:/nix/.base/bin:/nix/.bin";
        cmd.env("PATH", format!("{nix_bin_path}:{proc_path}"));

        if let Ok(term) = std::env::var("TERM") {
            cmd.env("TERM", term);
        } else {
            cmd.env("TERM", "xterm");
        }

        if let Ok(lang) = std::env::var("LANG") {
            cmd.env("LANG", lang);
        } else {
            cmd.env("LANG", "C.UTF-8");
        }

        let prompt = format!(
            "%F{{cyan}}({}) %F{{blue}}%~ %(?.%F{{green}}.%F{{red}})%#%f ",
            self.name,
        );
        cmd.env("PROMPT", &prompt);

        let nix_base = "/nix/.base";
        let data_dir = format!("/usr/local/share:/usr/share:{nix_base}/share");
        cmd.envs([
            ("ZDOTDIR", "/nix/etc"),
            ("NIX_CONF_DIR", "/nix/etc"),
            ("XDG_CACHE_HOME", "/nix/.cache"),
            ("XDG_CONFIG_HOME", "/nix/.config"),
            ("XDG_DATA_DIR", &data_dir),
        ]);

        cmd.envs([
            ("TERMINFO_DIRS", format!("{nix_base}/share/terminfo")),
            ("LIBEXEC_PATH", format!("{nix_base}/libexec")),
            ("INFOPATH", format!("{nix_base}/share/info")),
        ]);

        let err = cmd.exec();
        bail!("cannot exec: {}", err)
    }

    pub fn spawn(self) -> Result<()> {
        match unsafe { fork()? } {
            Fork::Child(_) => {
                if let Err(err) = self.exec() {
                    log::error!("cannot execute shell: {err}");
                    exit(1);
                }
                exit(0);
            }
            Fork::Parent(child_pid) => wait_for_child(child_pid),
        }
    }
}

pub fn wait_for_child(child_pid: rustix::thread::Pid) -> Result<()> {
    // TODO: propagate return code properly
    log::debug!("parent pid = {}", process::id());
    let _ = waitpid(Some(child_pid), WaitOptions::empty())
        .context("waitpid failed")?;
    Ok(())
}
