//! Application-level operational log.
//!
//! This is intentionally distinct from a vault's internal hash chain: the
//! hash chain is a tamper-evident *integrity* record stored inside a
//! specific `.rvlt` file, whereas this is a plain, human-readable
//! operational log for the application as a whole (vault created,
//! unlocked, locked out on timeout, file added, etc.).
//!
//! Never call [`log_event`] with anything that could contain a password,
//! derived key, or file plaintext -- only static, descriptive messages
//! and non-secret identifiers (vault names, file names) belong here.

use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use super::paths;

fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Plain seconds-since-epoch keeps this dependency-free; good enough
    // for an operational log meant to be read chronologically.
    format!("{secs}")
}

pub fn log_event(message: &str) {
    // Logging failures must never crash the app or the current operation;
    // best-effort only.
    let _ = try_log_event(message);
}

fn try_log_event(message: &str) -> io::Result<()> {
    let path = paths::log_file();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "[{}] {}", timestamp(), message)
}

/// Returns up to the last `n` log lines, oldest of that window first.
pub fn read_recent(n: usize) -> Vec<String> {
    let path = paths::log_file();
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let lines: Vec<String> = io::BufReader::new(file).lines().map_while(Result::ok).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_event_appends_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("REVAULT_HOME", dir.path());
        }
        log_event("vault created: Demo");
        log_event("vault unlocked: Demo");
        let recent = read_recent(10);
        assert_eq!(recent.len(), 2);
        assert!(recent[0].contains("vault created: Demo"));
        assert!(recent[1].contains("vault unlocked: Demo"));
        unsafe {
            std::env::remove_var("REVAULT_HOME");
        }
    }

    #[test]
    fn read_recent_truncates_to_last_n_lines() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("REVAULT_HOME", dir.path());
        }
        for i in 0..5 {
            log_event(&format!("event {i}"));
        }
        let recent = read_recent(2);
        assert_eq!(recent.len(), 2);
        assert!(recent[0].contains("event 3"));
        assert!(recent[1].contains("event 4"));
        unsafe {
            std::env::remove_var("REVAULT_HOME");
        }
    }
}
