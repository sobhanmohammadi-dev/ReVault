//! The Network tab: everything about connecting to other people over
//! the network lives here, and only here -- joining someone else's
//! vault, and for whichever vault you currently have unlocked, granting
//! or revoking peer access and serving it to those peers. The Vaults
//! tab stays purely about the vaults/files themselves; this tab owns
//! "connections, peer-to-peer, sending" so the two don't get tangled
//! back together.
//!
//! The one piece of state that necessarily lives elsewhere is the live
//! `NetworkSession` (serving bridge + patch journal) itself, defined
//! here but stored on `UnlockedState` -- its lifecycle has to be tied
//! to the specific vault being open, so it gets torn down automatically
//! when that vault locks, from wherever the lock happens.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame,
};

use crate::core::identity::{Identity, PeerId};
use crate::net::{InviteCode, PatchJournal};
use crate::tui::app::App;
use crate::tui::log;
use crate::tui::network_bridge::{self, NetworkBridge};
use crate::tui::widgets::vaults::{unlocked::UnlockedState, Mode as VaultsMode};

/// A live serving session: the network bridge plus the journal used to
/// answer reconnecting peers with a small patch instead of a full resync
/// (see `net::journal` docs). Torn down (and the background thread
/// signaled to stop) on lock/drop.
pub struct NetworkSession {
    pub bridge: NetworkBridge,
    pub journal: PatchJournal,
}

/// The Network tab's own UI state -- independent of which vault (if
/// any) is currently unlocked, since joining a new vault doesn't
/// require one.
pub struct NetworkTabWidget {
    pub mode: NetworkTabMode,
    pub recipients_selected: usize,
}

impl Default for NetworkTabWidget {
    fn default() -> Self {
        NetworkTabWidget { mode: NetworkTabMode::Idle, recipients_selected: 0 }
    }
}

pub enum NetworkTabMode {
    /// Browsing: peer list (for whichever vault is unlocked, if any)
    /// and serving status, no form open.
    Idle,
    /// Joining a vault as a peer -- works with no vault unlocked.
    Joining { input: String, error: Option<String> },
    /// Granting a peer access to the currently unlocked vault.
    Granting { input: String, error: Option<String> },
    /// Confirming the admin password before revoking -- `revoke_access`
    /// needs it to rewrap the rotated key for the admin's own slot, and
    /// the app deliberately doesn't hold the password in memory after
    /// unlock, so it has to be asked for again here.
    ConfirmRevoke { target: PeerId, password: String, error: Option<String> },
    /// Picking a port to start serving the currently unlocked vault on.
    ServePrompt { port_input: String, error: Option<String> },
}

pub fn is_modal(widget: &NetworkTabWidget) -> bool {
    !matches!(widget.mode, NetworkTabMode::Idle)
}

fn current_unlocked_mut(app: &mut App) -> Option<&mut UnlockedState> {
    match &mut app.vaults.mode {
        VaultsMode::Unlocked(state) => Some(state),
        _ => None,
    }
}

fn current_unlocked(app: &App) -> Option<&UnlockedState> {
    match &app.vaults.mode {
        VaultsMode::Unlocked(state) => Some(state),
        _ => None,
    }
}

/// Called once per TUI tick (not just on key presses), regardless of
/// which tab is selected, so a serving session keeps answering peers
/// even while the user is looking at another tab.
pub fn poll_network(state: &mut UnlockedState) {
    let Some(net) = &mut state.network else { return };

    while let Ok(event) = net.bridge.event_rx.try_recv() {
        match event {
            network_bridge::BridgeEvent::Synced(peer_id) => {
                state.message = Some(format!("Synced {}", peer_id.fingerprint()));
                log::log_event(&format!("peer synced: {} on vault \"{}\"", peer_id.fingerprint(), state.name));
            }
            network_bridge::BridgeEvent::Failed(e) => {
                state.message = Some(format!("Sync failed: {e}"));
            }
        }
    }

    if let Ok(network_bridge::SyncRequest::Incoming { peer_id, next_seq, respond_to }) = net.bridge.request_rx.try_recv() {
        let granted = state
            .vault
            .list_recipients()
            .map(|rs| rs.into_iter().any(|r| r.peer_id == peer_id))
            .unwrap_or(false);

        let response = if !granted {
            network_bridge::SyncResponse::NotGranted
        } else {
            match net.journal.ranges_since(next_seq) {
                Some(ranges) => network_bridge::SyncResponse::Message(crate::net::SyncMessage::Patch { seq: next_seq, ranges }),
                None => match state.vault.export_full() {
                    Ok(bytes) => network_bridge::SyncResponse::Message(crate::net::SyncMessage::FullSync { bytes }),
                    Err(e) => network_bridge::SyncResponse::Message(crate::net::SyncMessage::Error { message: e.to_string() }),
                },
            }
        };
        let _ = respond_to.send(response);
    }
}

fn try_join(app: &App, invite_str: &str) -> Result<(), String> {
    let invite = InviteCode::decode(invite_str.trim()).map_err(|e| e.to_string())?;
    let addr = invite
        .address
        .ok_or_else(|| "This invite code has no address to connect to.".to_string())?;

    let vaults_dir = app.vaults.vaults_dir();
    std::fs::create_dir_all(vaults_dir).map_err(|e| e.to_string())?;
    let path = vaults_dir.join(format!("joined-{}.rvlt", invite.peer_id.fingerprint()));
    if path.exists() {
        return Err("A replica from this peer already exists in your vaults directory.".to_string());
    }

    let my_identity = Identity::from_bytes(&app.vaults.identity_bytes());
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let joined = runtime
        .block_on(crate::net::sync::join(addr, &my_identity, &invite.peer_id, &path))
        .map_err(|e| e.to_string())?;
    let vault_name = joined.summary().name;
    drop(joined);

    log::log_event(&format!("joined vault \"{vault_name}\" as a peer via {addr}"));
    Ok(())
}

fn submit_grant(state: &mut UnlockedState, input: &str) -> Result<(), String> {
    let invite = InviteCode::decode(input.trim()).map_err(|e| e.to_string())?;
    state.vault.grant_access(&invite.peer_id).map_err(|e| e.to_string())?;
    log::log_event(&format!(
        "granted access to {} on vault \"{}\"",
        invite.peer_id.fingerprint(),
        state.name
    ));
    Ok(())
}

fn submit_revoke(state: &mut UnlockedState, target: &PeerId, password: &str) -> Result<(), String> {
    state.vault.revoke_access(&target.signing_public, password).map_err(|e| e.to_string())?;
    log::log_event(&format!(
        "revoked access from {} on vault \"{}\" (key rotated)",
        target.fingerprint(),
        state.name
    ));
    Ok(())
}

fn start_serving(state: &mut UnlockedState, port: u16) -> Result<(), String> {
    let addr: std::net::SocketAddr = ([0, 0, 0, 0], port).into();
    let bridge = NetworkBridge::start(addr, state.local_identity_bytes).map_err(|e| e.to_string())?;
    log::log_event(&format!("started serving vault \"{}\" on port {port}", state.name));
    state.network = Some(NetworkSession { bridge, journal: PatchJournal::new(64) });
    Ok(())
}

fn stop_serving(state: &mut UnlockedState) {
    if state.network.take().is_some() {
        log::log_event(&format!("stopped serving vault \"{}\"", state.name));
    }
}

pub fn handle_key(app: &mut App, key: KeyEvent) {
    if let Some(state) = current_unlocked_mut(app) {
        state.session.record_activity();
    }

    let mode = std::mem::replace(&mut app.network_ui.mode, NetworkTabMode::Idle);

    let new_mode = match mode {
        NetworkTabMode::Idle => match key.code {
            KeyCode::Char('j') => NetworkTabMode::Joining { input: String::new(), error: None },

            KeyCode::Char('g') if current_unlocked(app).is_some() => {
                NetworkTabMode::Granting { input: String::new(), error: None }
            }

            KeyCode::Char('r') => {
                let recipients = current_unlocked_mut(app).and_then(|state| state.vault.list_recipients().ok());
                let target = recipients.and_then(|rs| rs.get(app.network_ui.recipients_selected).map(|r| r.peer_id));
                match target {
                    Some(target) => NetworkTabMode::ConfirmRevoke { target, password: String::new(), error: None },
                    None => NetworkTabMode::Idle,
                }
            }

            KeyCode::Char('n') => {
                let currently_serving = current_unlocked(app).is_some_and(|s| s.network.is_some());
                if currently_serving {
                    if let Some(state) = current_unlocked_mut(app) {
                        stop_serving(state);
                    }
                    NetworkTabMode::Idle
                } else if current_unlocked(app).is_some() {
                    NetworkTabMode::ServePrompt { port_input: String::new(), error: None }
                } else {
                    NetworkTabMode::Idle
                }
            }

            KeyCode::Up => {
                app.network_ui.recipients_selected = app.network_ui.recipients_selected.saturating_sub(1);
                NetworkTabMode::Idle
            }
            KeyCode::Down => {
                let len = current_unlocked_mut(app).and_then(|s| s.vault.list_recipients().ok()).map(|r| r.len()).unwrap_or(0);
                if app.network_ui.recipients_selected + 1 < len {
                    app.network_ui.recipients_selected += 1;
                }
                NetworkTabMode::Idle
            }

            _ => NetworkTabMode::Idle,
        },

        NetworkTabMode::Joining { mut input, error } => match key.code {
            KeyCode::Esc => NetworkTabMode::Idle,
            KeyCode::Backspace => {
                input.pop();
                NetworkTabMode::Joining { input, error }
            }
            KeyCode::Char(c) => {
                input.push(c);
                NetworkTabMode::Joining { input, error }
            }
            KeyCode::Enter => match try_join(app, &input) {
                Ok(()) => {
                    app.vaults.refresh();
                    NetworkTabMode::Idle
                }
                Err(e) => NetworkTabMode::Joining { input, error: Some(e) },
            },
            _ => NetworkTabMode::Joining { input, error },
        },

        NetworkTabMode::Granting { mut input, error } => match key.code {
            KeyCode::Esc => NetworkTabMode::Idle,
            KeyCode::Backspace => {
                input.pop();
                NetworkTabMode::Granting { input, error }
            }
            KeyCode::Char(c) => {
                input.push(c);
                NetworkTabMode::Granting { input, error }
            }
            KeyCode::Enter => match current_unlocked_mut(app) {
                Some(state) => match submit_grant(state, &input) {
                    Ok(()) => NetworkTabMode::Idle,
                    Err(e) => NetworkTabMode::Granting { input, error: Some(e) },
                },
                None => NetworkTabMode::Idle,
            },
            _ => NetworkTabMode::Granting { input, error },
        },

        NetworkTabMode::ConfirmRevoke { target, mut password, error } => match key.code {
            KeyCode::Esc => NetworkTabMode::Idle,
            KeyCode::Backspace => {
                password.pop();
                NetworkTabMode::ConfirmRevoke { target, password, error }
            }
            KeyCode::Char(c) => {
                password.push(c);
                NetworkTabMode::ConfirmRevoke { target, password, error }
            }
            KeyCode::Enter => {
                let result = match current_unlocked_mut(app) {
                    Some(state) => submit_revoke(state, &target, &password),
                    None => Ok(()),
                };
                match result {
                    Ok(()) => {
                        app.network_ui.recipients_selected = 0;
                        NetworkTabMode::Idle
                    }
                    Err(e) => NetworkTabMode::ConfirmRevoke { target, password: String::new(), error: Some(e) },
                }
            }
            _ => NetworkTabMode::ConfirmRevoke { target, password, error },
        },

        NetworkTabMode::ServePrompt { mut port_input, error } => match key.code {
            KeyCode::Esc => NetworkTabMode::Idle,
            KeyCode::Backspace => {
                port_input.pop();
                NetworkTabMode::ServePrompt { port_input, error }
            }
            KeyCode::Char(c) if c.is_ascii_digit() => {
                port_input.push(c);
                NetworkTabMode::ServePrompt { port_input, error }
            }
            KeyCode::Enter => match port_input.trim().parse::<u16>() {
                Ok(port) => match current_unlocked_mut(app) {
                    Some(state) => match start_serving(state, port) {
                        Ok(()) => NetworkTabMode::Idle,
                        Err(e) => NetworkTabMode::ServePrompt { port_input, error: Some(e) },
                    },
                    None => NetworkTabMode::Idle,
                },
                Err(_) => NetworkTabMode::ServePrompt { port_input, error: Some("Enter a valid port number (1-65535)".to_string()) },
            },
            _ => NetworkTabMode::ServePrompt { port_input, error },
        },
    };

    app.network_ui.mode = new_mode;
}

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    match &app.network_ui.mode {
        NetworkTabMode::Idle => render_idle(frame, area, app),
        NetworkTabMode::Joining { input, error } => {
            render_text_prompt(frame, area, " Peer's invite code (from their `whoami --listen`) ", input, error.as_deref())
        }
        NetworkTabMode::Granting { input, error } => {
            render_text_prompt(frame, area, " Peer's invite code (from their `whoami`) ", input, error.as_deref())
        }
        NetworkTabMode::ConfirmRevoke { target, password, error } => render_confirm_revoke(frame, area, target, password, error),
        NetworkTabMode::ServePrompt { port_input, error } => {
            render_text_prompt(frame, area, " Port to serve on (peers connect here) ", port_input, error.as_deref())
        }
    }
}

fn render_idle(frame: &mut Frame, area: Rect, app: &App) {
    let layout = Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1)]);
    let [identity_a, status_a, list_a, message_a] = area.layout(&layout);

    let identity = Identity::from_bytes(&app.vaults.identity_bytes());
    let identity_line = Paragraph::new(Line::from(format!("Your identity: {}", identity.peer_id().fingerprint())));
    frame.render_widget(identity_line, identity_a);

    let Some(state) = current_unlocked(app) else {
        let status = Paragraph::new(Line::from("No vault unlocked."));
        frame.render_widget(status, status_a);
        let placeholder = Paragraph::new(
            "Press 'j' to join a peer's vault. Unlock a vault from the Vaults tab to grant/revoke access or serve it to peers.",
        )
        .alignment(Alignment::Center);
        frame.render_widget(placeholder, list_a);
        return;
    };

    let serving_status = match &state.network {
        Some(net) => format!("Serving \"{}\" on port {}.", state.name, net.bridge.listen_addr.port()),
        None => format!("\"{}\" unlocked, not serving.", state.name),
    };
    frame.render_widget(Paragraph::new(Line::from(serving_status)), status_a);

    let recipients = state.vault.list_recipients().unwrap_or_default();
    let header = Row::new(["Fingerprint", "Granted at"]).style(Style::new().bold()).bottom_margin(1);
    let rows: Vec<Row> = recipients
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let style = if i == app.network_ui.recipients_selected {
                Style::default().fg(Color::Rgb(255, 140, 0))
            } else {
                Style::default()
            };
            Row::new([r.peer_id.fingerprint(), r.granted_at.to_string()]).style(style)
        })
        .collect();
    let table = Table::new(rows, [Constraint::Length(20), Constraint::Length(16)]).header(header);
    frame.render_widget(table, list_a);

    let hint = Paragraph::new(Line::from(
        "'j' join a vault, 'g' grant this vault, 'r' revoke selected, 'n' serve/stop.",
    ));
    frame.render_widget(hint, message_a);
}

fn render_text_prompt(frame: &mut Frame, area: Rect, title: &str, value: &str, error: Option<&str>) {
    let layout = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]);
    let [field_a, error_a] = area.layout(&layout);

    let block = Block::default().borders(Borders::ALL).title(title).border_style(Style::default().fg(Color::Rgb(255, 140, 0)));
    frame.render_widget(Paragraph::new(Line::from(value)).block(block), field_a);

    if let Some(err) = error {
        let error_line = Paragraph::new(Line::from(err)).style(Style::default().fg(Color::Red));
        frame.render_widget(error_line, error_a);
    }
}

fn render_confirm_revoke(frame: &mut Frame, area: Rect, target: &PeerId, password: &str, error: &Option<String>) {
    let layout = Layout::vertical([Constraint::Length(1), Constraint::Length(3), Constraint::Fill(1)]);
    let [label_a, pass_a, error_a] = area.layout(&layout);

    let label = Paragraph::new(Line::from(format!("Revoke {} -- confirm the vault password", target.fingerprint())));
    frame.render_widget(label, label_a);

    let masked = "*".repeat(password.chars().count());
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Password ")
        .border_style(Style::default().fg(Color::Rgb(255, 140, 0)));
    frame.render_widget(Paragraph::new(Line::from(masked)).block(block), pass_a);

    if let Some(err) = error {
        let error_line = Paragraph::new(Line::from(err.as_str())).style(Style::default().fg(Color::Red));
        frame.render_widget(error_line, error_a);
    }
}
