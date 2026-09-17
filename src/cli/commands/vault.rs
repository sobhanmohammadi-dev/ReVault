//! CLI entry points for direct vault/file management -- the
//! non-network counterparts to `network.rs`, giving the CLI full parity
//! with what the TUI's Vaults tab can do (plus `update`, which the CLI
//! reaches before the TUI does -- see the TUI's own `u` key for that).

use std::path::PathBuf;

use crate::core::{Identity, Vault};

use super::to_io_err;

/// Parses capacities like "10 GB", "500MB", "1 TB", or a bare byte
/// count. Kept in one place per call site (TUI has its own copy in
/// `tui::widgets::vaults`) rather than plumbed through a shared module,
/// since it's small, self-contained, and duplicating it is lower risk
/// than refactoring already-working code to share it.
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

pub struct Create;

impl Create {
    pub fn execute(path: PathBuf, name: String, description: String, capacity: String, password: String) -> std::io::Result<()> {
        let capacity_bytes = parse_capacity(&capacity).map_err(to_io_err)?;
        let admin_identity = Identity::load_or_create()?;
        let vault = Vault::create(&path, &name, &description, capacity_bytes, &password, admin_identity).map_err(to_io_err)?;
        println!(
            "Created \"{}\" at {} ({} capacity).",
            name,
            path.display(),
            format_bytes(vault.capacity_bytes())
        );
        Ok(())
    }
}

pub struct List;

impl List {
    pub fn execute(vault: PathBuf, password: String) -> std::io::Result<()> {
        let local_identity = Identity::load_or_create()?;
        let mut v = Vault::open(&vault, &password, local_identity).map_err(to_io_err)?;
        let files = v.list_files().map_err(to_io_err)?;
        println!(
            "\"{}\" -- {} used of {} -- {} file(s):",
            v.summary().name,
            format_bytes(v.used_bytes()),
            format_bytes(v.capacity_bytes()),
            files.len()
        );
        for f in files {
            println!("  {}  ({}, modified {})", f.name, format_bytes(f.size), f.modified_at);
        }
        Ok(())
    }
}

pub struct Verify;

impl Verify {
    pub fn execute(vault: PathBuf, password: String) -> std::io::Result<()> {
        let local_identity = Identity::load_or_create()?;
        let mut v = Vault::open(&vault, &password, local_identity).map_err(to_io_err)?;
        v.verify_integrity().map_err(to_io_err)?;
        println!("Integrity check passed: chain linkage, admin signatures, and file hashes all verified.");
        Ok(())
    }
}

pub struct Add;

impl Add {
    pub fn execute(vault: PathBuf, password: String, source: PathBuf, name: String) -> std::io::Result<()> {
        let local_identity = Identity::load_or_create()?;
        let mut v = Vault::open(&vault, &password, local_identity).map_err(to_io_err)?;
        let data = std::fs::read(&source)?;
        let len = data.len();
        v.add_file(&name, &data).map_err(to_io_err)?;
        println!("Added \"{name}\" ({}).", format_bytes(len as u64));
        Ok(())
    }
}

pub struct Update;

impl Update {
    pub fn execute(vault: PathBuf, password: String, source: PathBuf, name: String) -> std::io::Result<()> {
        let local_identity = Identity::load_or_create()?;
        let mut v = Vault::open(&vault, &password, local_identity).map_err(to_io_err)?;
        let data = std::fs::read(&source)?;
        let len = data.len();
        v.update_file(&name, &data).map_err(to_io_err)?;
        println!("Updated \"{name}\" ({}).", format_bytes(len as u64));
        Ok(())
    }
}

pub struct Delete;

impl Delete {
    pub fn execute(vault: PathBuf, password: String, name: String) -> std::io::Result<()> {
        let local_identity = Identity::load_or_create()?;
        let mut v = Vault::open(&vault, &password, local_identity).map_err(to_io_err)?;
        v.delete_file(&name).map_err(to_io_err)?;
        println!("Deleted \"{name}\".");
        Ok(())
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}
