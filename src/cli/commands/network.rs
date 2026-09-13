//! CLI entry points for the network feature: sharing your identity,
//! granting/revoking peer access, serving a vault to granted peers, and
//! joining a vault as a granted peer.
//!
//! These wrap the async `revault::net` API in a one-off Tokio runtime
//! per invocation, since the rest of the CLI/TUI is synchronous.

use std::net::SocketAddr;
use std::path::PathBuf;

use tokio::io::AsyncBufReadExt;

use crate::core::{Identity, Vault};
use crate::net::{sync, InviteCode, PatchJournal};

pub struct Whoami;

impl Whoami {
    /// Prints this device's shareable invite code. Pass `listen` if this
    /// device intends to run `serve` so the invite embeds an address a
    /// peer can dial directly; otherwise the invite carries identity only
    /// and the address must be arranged some other way.
    pub fn execute(listen: Option<SocketAddr>) -> std::io::Result<()> {
        let identity = Identity::load_or_create()?;
        let invite = InviteCode { peer_id: identity.peer_id(), address: listen };
        println!("Your identity fingerprint: {}", identity.peer_id().fingerprint());
        println!("Invite code (share this with whoever should grant you access,");
        println!("or with a peer you're about to grant access to):");
        println!("{}", invite.encode());
        Ok(())
    }
}

pub struct Grant;

impl Grant {
    pub fn execute(vault: PathBuf, password: String, peer_invite: String) -> std::io::Result<()> {
        let invite = InviteCode::decode(&peer_invite).map_err(to_io_err)?;
        let local_identity = Identity::load_or_create()?;
        let mut v = Vault::open(&vault, &password, local_identity).map_err(to_io_err)?;
        v.grant_access(&invite.peer_id).map_err(to_io_err)?;
        println!("Granted access to {}", invite.peer_id.fingerprint());
        Ok(())
    }
}

pub struct Revoke;

impl Revoke {
    pub fn execute(vault: PathBuf, password: String, peer_invite: String) -> std::io::Result<()> {
        let invite = InviteCode::decode(&peer_invite).map_err(to_io_err)?;
        let local_identity = Identity::load_or_create()?;
        let mut v = Vault::open(&vault, &password, local_identity).map_err(to_io_err)?;
        v.revoke_access(&invite.peer_id.signing_public, &password).map_err(to_io_err)?;
        println!(
            "Revoked access from {} and rotated the vault's encryption key.",
            invite.peer_id.fingerprint()
        );
        Ok(())
    }
}

pub struct Serve;

impl Serve {
    /// Runs an interactive serving session: accepts connections from
    /// granted peers *and* reads simple admin commands from stdin, on a
    /// single `Vault` handle. Doing both on one handle in one task (via
    /// `tokio::select!`) is deliberate -- it's what makes it safe to keep
    /// a `PatchJournal` that actually gets populated. Running a second,
    /// separate process (e.g. `revault grant` while `serve` is also
    /// running) against the same vault file at the same time is NOT
    /// safe and isn't supported: each `Vault` handle caches its own copy
    /// of the header/allocator in memory, so two independent processes
    /// writing to the same file could corrupt it. Use the `add`/`update`/
    /// `delete` commands inside this session instead of a separate CLI
    /// invocation while `serve` is running.
    pub fn execute(vault: PathBuf, password: String, listen: SocketAddr) -> std::io::Result<()> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async move {
            let local_identity = Identity::load_or_create()?;
            let mut v = Vault::open(&vault, &password, local_identity).map_err(to_io_err)?;
            let mut journal = PatchJournal::new(64);

            let listener = tokio::net::TcpListener::bind(listen).await?;
            println!("Serving \"{}\" on {listen}.", v.summary().name);
            println!("Granted peers can sync now. Type 'help' for admin commands.");

            let stdin = tokio::io::BufReader::new(tokio::io::stdin());
            let mut lines = stdin.lines();

            loop {
                print!("> ");
                {
                    use std::io::Write as _;
                    let _ = std::io::stdout().flush();
                }

                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, _addr)) => {
                                let listener_identity = Identity::load_or_create()?;
                                match sync::serve_stream(stream, &listener_identity, &mut v, Some(&journal)).await {
                                    Ok(peer_id) => println!("\nSynced {} successfully.", peer_id.fingerprint()),
                                    Err(e) => eprintln!("\nA peer connection failed: {e}"),
                                }
                            }
                            Err(e) => eprintln!("\naccept error: {e}"),
                        }
                    }
                    line = lines.next_line() => {
                        let Some(line) = line? else {
                            break; // stdin closed
                        };
                        match Self::handle_command(&mut v, &mut journal, line.trim()) {
                            Ok(true) => {}
                            Ok(false) => break,
                            Err(e) => eprintln!("{e}"),
                        }
                    }
                }
            }
            Ok(())
        })
    }

    /// Returns `Ok(true)` to keep looping, `Ok(false)` to stop serving.
    fn handle_command(v: &mut Vault, journal: &mut PatchJournal, line: &str) -> std::io::Result<bool> {
        let mut parts = line.split_whitespace();
        match parts.next() {
            None | Some("help") => {
                println!("Commands:");
                println!("  add <source-path> <name>     import a file and push it to synced peers");
                println!("  update <source-path> <name>  replace a stored file's contents");
                println!("  delete <name>                remove a stored file");
                println!("  list                          list stored files");
                println!("  quit                          stop serving");
            }
            Some("list") => {
                for f in v.list_files().map_err(to_io_err)? {
                    println!("  {} ({} bytes)", f.name, f.size);
                }
            }
            Some("add") => {
                let (src, name) = two_args(parts).ok_or_else(|| usage_err("add <source-path> <name>"))?;
                let data = std::fs::read(&src)?;
                let (seq, _) = v.chain_state();
                v.add_file(&name, &data).map_err(to_io_err)?;
                journal.record(seq, v.take_change_log());
                println!("Added \"{name}\".");
            }
            Some("update") => {
                let (src, name) = two_args(parts).ok_or_else(|| usage_err("update <source-path> <name>"))?;
                let data = std::fs::read(&src)?;
                let (seq, _) = v.chain_state();
                v.update_file(&name, &data).map_err(to_io_err)?;
                journal.record(seq, v.take_change_log());
                println!("Updated \"{name}\".");
            }
            Some("delete") => {
                let name = parts.next().ok_or_else(|| usage_err("delete <name>"))?.to_string();
                let (seq, _) = v.chain_state();
                v.delete_file(&name).map_err(to_io_err)?;
                journal.record(seq, v.take_change_log());
                println!("Deleted \"{name}\".");
            }
            Some("quit") | Some("exit") => return Ok(false),
            Some(other) => println!("Unknown command '{other}'. Type 'help' for a list."),
        }
        Ok(true)
    }
}

fn two_args<'a>(mut parts: impl Iterator<Item = &'a str>) -> Option<(String, String)> {
    let a = parts.next()?.to_string();
    let b = parts.next()?.to_string();
    Some((a, b))
}

fn usage_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("usage: {msg}"))
}

pub struct Join;

impl Join {
    pub fn execute(invite: String, out: PathBuf) -> std::io::Result<()> {
        let invite = InviteCode::decode(&invite).map_err(to_io_err)?;
        let addr = invite.address.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "this invite code has no address to connect to")
        })?;
        let local_identity = Identity::load_or_create()?;

        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async move {
            let mut v = sync::join(addr, &local_identity, &invite.peer_id, &out).await.map_err(to_io_err)?;
            let files = v.list_files().map_err(to_io_err)?;
            println!("Joined vault \"{}\" -- {} file(s) available:", v.summary().name, files.len());
            for f in files {
                println!("  {} ({} bytes)", f.name, f.size);
            }
            Ok(())
        })
    }
}

fn to_io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}
