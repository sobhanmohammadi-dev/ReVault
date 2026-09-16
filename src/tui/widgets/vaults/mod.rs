//! Vaults tab: browse `.rvlt` files found in the configured vaults
//! directory, create new ones, unlock, and operate on an unlocked
//! vault's files. Vault/file management only -- peer access
//! (grant/revoke), joining someone else's vault, and serving to peers
//! all live in the Network tab (`tui::widgets::network_tab`) instead.
//! The vaults directory is just a plain folder scan -- there is no
//! sidecar index -- each `.rvlt` file remains independently
//! self-contained and openable on its own.

pub mod create;
pub mod table;
pub mod unlock;
pub mod unlocked;

use std::path::{Path, PathBuf};

use crossterm::event::KeyEvent;
use ratatui::{layout::Rect, Frame};

use crate::core::{self, Identity, VaultError};
use crate::tui::log;

use create::{CreateForm, CreateOutcome};
use unlock::{UnlockForm, UnlockOutcome};
use unlocked::UnlockedState;

#[derive(Debug, Clone)]
pub struct VaultListing {
    pub path: PathBuf,
    pub name: String,
    pub description: String,
    pub capacity_bytes: u64,
}

pub enum Mode {
    Browsing,
    Creating(CreateForm),
    Unlocking(UnlockForm, PathBuf, String),
    Unlocked(UnlockedState),
}

pub struct App {
    pub vaults_dir: PathBuf,
    pub listing: Vec<VaultListing>,
    pub selected: usize,
    pub mode: Mode,
    /// This device's local identity. For a freshly created vault this
    /// becomes the vault's admin identity; for an existing vault, whether
    /// it grants admin rights depends on whether it matches the identity
    /// recorded at that vault's creation time. Also used by the Network
    /// tab (joining, displaying this device's invite fingerprint) via
    /// `identity_bytes()`.
    identity: Identity,
}

fn scan_vaults_dir(dir: &Path) -> Vec<VaultListing> {
    let _ = std::fs::create_dir_all(dir);
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rvlt") {
            continue;
        }
        if let Ok(summary) = core::Vault::peek_summary(&path) {
            out.push(VaultListing {
                path,
                name: summary.name,
                description: summary.description,
                capacity_bytes: summary.capacity_bytes,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Parses capacities like "10 GB", "500MB", "1 TB", or a bare byte count.
fn parse_capacity(input: &str) -> Result<u64, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("Capacity is required".to_string());
    }
    let lower = s.to_lowercase();
    let (number_part, multiplier): (&str, u64) = if let Some(n) = lower.strip_suffix("tb") {
        (n, 1024 * 1024 * 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix("gb") {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix("mb") {
        (n, 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix("kb") {
        (n, 1024)
    } else if let Some(n) = lower.strip_suffix('b') {
        (n, 1)
    } else {
        (lower.as_str(), 1)
    };
    let number: f64 = number_part.trim().parse().map_err(|_| "Could not parse capacity number".to_string())?;
    if number <= 0.0 {
        return Err("Capacity must be greater than zero".to_string());
    }
    Ok((number * multiplier as f64) as u64)
}

fn slugify(name: &str) -> String {
    let mut out = String::new();
    for c in name.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "vault".to_string()
    } else {
        trimmed
    }
}

fn unique_vault_path(dir: &Path, name: &str) -> PathBuf {
    let base = slugify(name);
    let mut candidate = dir.join(format!("{base}.rvlt"));
    let mut n = 2;
    while candidate.exists() {
        candidate = dir.join(format!("{base}-{n}.rvlt"));
        n += 1;
    }
    candidate
}

impl App {
    pub fn new_with_dir(vaults_dir: PathBuf) -> Self {
        let listing = scan_vaults_dir(&vaults_dir);
        // Best-effort: if the identity file can't be read/written for some
        // reason, fall back to an in-memory identity for this session
        // rather than crashing the whole app -- it just means this
        // session won't have durable admin rights across restarts.
        let identity = Identity::load_or_create().unwrap_or_else(|_| Identity::generate());
        App { vaults_dir, listing, selected: 0, mode: Mode::Browsing, identity }
    }

    pub fn refresh(&mut self) {
        self.listing = scan_vaults_dir(&self.vaults_dir);
        if self.selected >= self.listing.len() {
            self.selected = self.listing.len().saturating_sub(1);
        }
    }

    pub fn vaults_dir(&self) -> &Path {
        &self.vaults_dir
    }

    /// Byte copy of this device's local identity -- used by the Network
    /// tab (joining a vault, displaying this device's invite
    /// fingerprint) without needing to duplicate identity loading there.
    pub fn identity_bytes(&self) -> [u8; 64] {
        self.identity.to_bytes()
    }

    /// True whenever `q`/`Esc` should be handled locally (locking a
    /// vault, cancelling a form) rather than quitting the whole app.
    pub fn intercepts_quit(&self) -> bool {
        !matches!(self.mode, Mode::Browsing)
    }

    /// True whenever `Tab` has a local meaning (moving between fields in
    /// a form) and shouldn't switch app tabs. Deliberately *not* true
    /// for a plain unlocked vault with no form open, so the user can
    /// still jump to the Network tab to manage that vault's peers.
    pub fn blocks_tab_switch(&self) -> bool {
        match &self.mode {
            Mode::Browsing => false,
            Mode::Unlocked(state) => state.add_form.is_some(),
            Mode::Creating(_) | Mode::Unlocking(..) => true,
        }
    }

    /// Called every event-loop tick (not just on key presses) so
    /// wall-clock-based behavior -- the 30s inactivity timeout, and
    /// answering pending network sync requests for whichever vault is
    /// unlocked -- happens even when the user hasn't pressed anything
    /// recently, and regardless of which tab is currently selected.
    pub fn check_timeout(&mut self) {
        if let Mode::Unlocked(state) = &mut self.mode {
            if state.session.is_expired() {
                log::log_event(&format!("vault auto-locked after inactivity: {}", state.name));
                self.mode = Mode::Browsing;
                self.refresh();
                return;
            }
            crate::tui::widgets::network_tab::poll_network(state);
        }
    }

    fn try_create(&self, form: &CreateForm) -> Result<(), String> {
        let name = form.name.trim();
        if name.is_empty() {
            return Err("Name is required".to_string());
        }
        if form.password.is_empty() {
            return Err("Password is required".to_string());
        }
        if form.password != form.confirm {
            return Err("Passwords do not match".to_string());
        }
        let capacity_bytes = parse_capacity(&form.capacity)?;
        std::fs::create_dir_all(&self.vaults_dir).map_err(|e| e.to_string())?;
        let path = unique_vault_path(&self.vaults_dir, name);
        let admin_identity = Identity::from_bytes(&self.identity.to_bytes());
        core::Vault::create(&path, name, form.description.trim(), capacity_bytes, &form.password, admin_identity)
            .map_err(|e| e.to_string())?;
        log::log_event(&format!("vault created: {name}"));
        Ok(())
    }

    pub fn create(&mut self) {
        self.mode = Mode::Creating(CreateForm::default());
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        let mode = std::mem::replace(&mut self.mode, Mode::Browsing);
        self.mode = self.process_key(mode, key);
        if matches!(self.mode, Mode::Browsing) {
            self.refresh();
        }
    }

    fn process_key(&mut self, mode: Mode, key: KeyEvent) -> Mode {
        use crossterm::event::KeyCode;

        match mode {
            Mode::Browsing => {
                match key.code {
                    KeyCode::Char('+') => return Mode::Creating(CreateForm::default()),
                    KeyCode::Up => {
                        self.selected = self.selected.saturating_sub(1);
                    }
                    KeyCode::Down => {
                        if self.selected + 1 < self.listing.len() {
                            self.selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(v) = self.listing.get(self.selected) {
                            return Mode::Unlocking(UnlockForm::default(), v.path.clone(), v.name.clone());
                        }
                    }
                    _ => {}
                }
                Mode::Browsing
            }

            Mode::Creating(mut form) => match create::handle_key(&mut form, key) {
                Some(CreateOutcome::Cancel) => Mode::Browsing,
                Some(CreateOutcome::Submit) => match self.try_create(&form) {
                    Ok(()) => Mode::Browsing,
                    Err(e) => {
                        form.error = Some(e);
                        Mode::Creating(form)
                    }
                },
                None => Mode::Creating(form),
            },

            Mode::Unlocking(mut form, path, name) => match unlock::handle_key(&mut form, key) {
                Some(UnlockOutcome::Cancel) => Mode::Browsing,
                Some(UnlockOutcome::Submit) => {
                    let identity_bytes = self.identity.to_bytes();
                    let local_identity = Identity::from_bytes(&identity_bytes);
                    match core::Vault::open(&path, &form.password, local_identity) {
                        Ok(vault) => {
                            log::log_event(&format!("vault unlocked: {name}"));
                            Mode::Unlocked(UnlockedState::new(vault, path, name, identity_bytes))
                        }
                        Err(VaultError::IncorrectPassword) => {
                            form.password.clear();
                            form.error = Some("Incorrect password".to_string());
                            Mode::Unlocking(form, path, name)
                        }
                        Err(e) => {
                            form.error = Some(e.to_string());
                            Mode::Unlocking(form, path, name)
                        }
                    }
                }
                None => Mode::Unlocking(form, path, name),
            },

            Mode::Unlocked(mut state) => match unlocked::handle_key(&mut state, key) {
                unlocked::Outcome::Lock => {
                    log::log_event(&format!("vault locked: {}", state.name));
                    Mode::Browsing
                }
                unlocked::Outcome::Continue => Mode::Unlocked(state),
            },
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        match &self.mode {
            Mode::Browsing => table::render(frame, area, &self.listing, self.selected),
            Mode::Creating(form) => create::render(frame, area, form),
            Mode::Unlocking(form, _path, name) => unlock::render(frame, area, name, form),
            Mode::Unlocked(state) => unlocked::render(frame, area, state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_capacity_units() {
        assert_eq!(parse_capacity("10 GB").unwrap(), 10 * 1024 * 1024 * 1024);
        assert_eq!(parse_capacity("500MB").unwrap(), 500 * 1024 * 1024);
        assert_eq!(parse_capacity("1tb").unwrap(), 1024 * 1024 * 1024 * 1024);
        assert_eq!(parse_capacity("2048").unwrap(), 2048);
    }

    #[test]
    fn parse_capacity_rejects_garbage() {
        assert!(parse_capacity("").is_err());
        assert!(parse_capacity("not a number").is_err());
        assert!(parse_capacity("-5 GB").is_err());
    }

    #[test]
    fn slugify_produces_filesystem_safe_names() {
        assert_eq!(slugify("My Cool Vault!"), "my-cool-vault");
        assert_eq!(slugify("   "), "vault");
        // Non-ASCII letters are treated as separators (kept ASCII-only for
        // filesystem-safety); only the ASCII consonants survive here.
        assert_eq!(slugify("Ünïcödé"), "n-c-d");
    }
}
