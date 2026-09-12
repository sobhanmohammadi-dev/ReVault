//! Filesystem locations used by the TUI shell itself.
//!
//! None of these are required to open or operate an individual `.rvlt`
//! vault -- a vault remains fully self-contained and can be opened by path
//! directly. These locations exist purely for the *application's* own
//! convenience: where it looks for vaults by default, where it persists
//! its own settings, and where it writes its own operational log.
//!
//! We deliberately avoid pulling in a platform-directories crate here
//! (kept the dependency surface minimal); `$REVAULT_HOME`, falling back to
//! `$HOME/.revault`, covers Linux/macOS developer environments well. On
//! platforms without `HOME` set this falls back to the current directory.

use std::path::PathBuf;

pub fn app_home_dir() -> PathBuf {
    if let Ok(p) = std::env::var("REVAULT_HOME") {
        return PathBuf::from(p);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".revault");
    }
    PathBuf::from(".revault")
}

pub fn default_vaults_dir() -> PathBuf {
    app_home_dir().join("vaults")
}

pub fn settings_file() -> PathBuf {
    app_home_dir().join("settings.cfg")
}

pub fn log_file() -> PathBuf {
    app_home_dir().join("revault.log")
}
