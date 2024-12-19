use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs::create_dir_all,
    os::unix::process::CommandExt,
    process::{exit, Command},
};

use anyhow::{Context, Result};
use itertools::Itertools;
use rustix::{
    process::{getpid, kill_process, waitpid, Signal, WaitOptions},
    runtime::{fork, Fork},
};

const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

pub struct Shell {
    name: String,
    env: HashMap<OsString, OsString>,
}

impl Shell {
    const NIX_ENVS: [&str; 2] = [crate::USER_ENV_DIR, crate::BASE_DIR];
    const BIN_DIRS: [&str; 2] = ["bin", "sbin"];

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

    pub fn spawn(self) -> Result<i32> {
        match unsafe { fork()? } {
            Fork::Child(_) => {
                let err = self.exec();
                log::error!("cannot execute shell: {err}");
                exit(1);
            }
            Fork::Parent(child_pid) => wait_for_child(child_pid),
        }
    }

    fn exec(self) -> std::io::Error {
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
        let nix_bin_path = Self::get_bin_paths();
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

        let share_paths = Self::get_env_paths("share");
        let data_dir = format!("{share_paths}:/usr/local/share:/usr/share");
        cmd.envs([
            ("ZDOTDIR", crate::ETC_DIR),
            ("NIX_CONF_DIR", crate::ETC_DIR),
            ("NIX_SSL_CERT_FILE", crate::SSL_CERTS),
            ("XDG_CACHE_HOME", crate::CACHE_HOME),
            ("XDG_CONFIG_HOME", crate::CONFIG_HOME),
            ("XDG_DATA_DIR", &data_dir),
        ]);

        cmd.envs([
            ("TERMINFO_DIRS", Self::get_env_paths("share/terminfo")),
            ("LIBEXEC_PATH", Self::get_env_paths("libexec")),
            ("INFOPATH", Self::get_env_paths("share/info")),
        ]);

        let _ = create_dir_all(crate::CACHE_HOME);
        cmd.exec()
    }

    fn get_bin_paths() -> String {
        Self::NIX_ENVS
            .iter()
            .cartesian_product(Self::BIN_DIRS)
            .map(|(env, dir)| format!("{env}/{dir}"))
            .join(":")
    }

    fn get_env_paths(dir: &str) -> String {
        Self::NIX_ENVS.map(|e| format!("{e}/{dir}")).join(":")
    }
}

pub fn wait_for_child(child_pid: rustix::thread::Pid) -> Result<i32> {
    loop {
        let maybe_wait_status = waitpid(Some(child_pid), WaitOptions::UNTRACED)
            .context("waitpid failed")?;

        if let Some(wait_status) = maybe_wait_status {
            if wait_status.stopped() {
                log::debug!("receveid SIGSTOP");
                let _ = kill_process(getpid(), Signal::Stop);
                let _ = kill_process(child_pid, Signal::Cont);
                continue;
            }

            if wait_status.exited() {
                let exit_status = wait_status.exit_status().unwrap() as i32;
                log::debug!("exit_status = {}", exit_status);
                return Ok(exit_status);
            }

            if wait_status.signaled() {
                let term_signal = wait_status.terminating_signal().unwrap();
                log::debug!("term_signal = {}", term_signal);
            }

            log::debug!("exit 1");
            return Ok(1);
        }
    }
}
