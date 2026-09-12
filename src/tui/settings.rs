//! Application-level settings.
//!
//! This is deliberately a tiny, hand-rolled `key=value` text file rather
//! than pulling in a config-format crate: the only setting we have right
//! now is where to look for vaults. This file lives alongside the app's
//! log file, never inside or next to a `.rvlt` container, so it never
//! violates the single-file vault invariant.

use std::fs;
use std::io;
use std::path::PathBuf;

use super::paths;

#[derive(Debug, Clone)]
pub struct AppSettings {
    pub vaults_dir: PathBuf,
}

impl AppSettings {
    pub fn load() -> Self {
        let path = paths::settings_file();
        let default = AppSettings { vaults_dir: paths::default_vaults_dir() };

        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return default,
        };

        let mut vaults_dir = default.vaults_dir.clone();
        for line in contents.lines() {
            if let Some(value) = line.strip_prefix("vaults_dir=") {
                if !value.trim().is_empty() {
                    vaults_dir = PathBuf::from(value.trim());
                }
            }
        }
        AppSettings { vaults_dir }
    }

    pub fn save(&self) -> io::Result<()> {
        let path = paths::settings_file();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = format!("vaults_dir={}\n", self.vaults_dir.display());
        fs::write(path, contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_falls_back_to_default_when_no_file_exists() {
        // SAFETY: single-threaded test process; setting env vars here is
        // only used to isolate this test's file location.
        unsafe {
            std::env::set_var("REVAULT_HOME", "/nonexistent/revault-home-for-tests-xyz");
        }
        let settings = AppSettings::load();
        assert_eq!(settings.vaults_dir, paths::default_vaults_dir());
        unsafe {
            std::env::remove_var("REVAULT_HOME");
        }
    }

    #[test]
    fn save_then_load_roundtrips_vaults_dir() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("REVAULT_HOME", dir.path());
        }
        let mut settings = AppSettings::load();
        settings.vaults_dir = dir.path().join("custom-vaults");
        settings.save().unwrap();

        let reloaded = AppSettings::load();
        assert_eq!(reloaded.vaults_dir, dir.path().join("custom-vaults"));
        unsafe {
            std::env::remove_var("REVAULT_HOME");
        }
    }
}
