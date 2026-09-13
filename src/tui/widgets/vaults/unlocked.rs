use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame,
};

use crate::core::{self, Session};
use crate::net::InviteCode;
use crate::tui::log;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddField {
    Source,
    Dest,
}

#[derive(Debug, Clone, Default)]
pub struct AddFileForm {
    pub source_path: String,
    pub dest_name: String,
    pub focus_dest: bool,
    pub error: Option<String>,
}

/// Sub-modes of the peer-management view.
pub enum PeersMode {
    /// Browsing the list of currently granted peers.
    Browsing,
    /// Typing in an invite code (from `whoami`/`revault whoami`) to grant.
    Granting { input: String, error: Option<String> },
    /// Confirming the admin password before revoking -- `revoke_access`
    /// needs it to rewrap the rotated key for the admin's own slot, and
    /// the TUI deliberately doesn't hold the password in memory after
    /// unlock, so it has to be asked for again here.
    ConfirmRevoke { target: core::PeerId, password: String, error: Option<String> },
}

pub struct PeersView {
    pub recipients: Vec<core::RecipientInfo>,
    pub selected: usize,
    pub mode: PeersMode,
}

pub struct UnlockedState {
    pub vault: core::Vault,
    pub path: PathBuf,
    pub name: String,
    pub files: Vec<core::FileInfo>,
    pub selected: usize,
    pub session: Session,
    pub message: Option<String>,
    pub add_form: Option<AddFileForm>,
    pub peers: Option<PeersView>,
}

impl UnlockedState {
    pub fn new(vault: core::Vault, path: PathBuf, name: String) -> Self {
        let mut state = UnlockedState {
            vault,
            path,
            name,
            files: Vec::new(),
            selected: 0,
            session: Session::new(),
            message: None,
            add_form: None,
            peers: None,
        };
        state.refresh_files();
        state
    }

    fn refresh_files(&mut self) {
        match self.vault.list_files() {
            Ok(files) => {
                self.files = files;
                if self.selected >= self.files.len() {
                    self.selected = self.files.len().saturating_sub(1);
                }
            }
            Err(e) => self.message = Some(format!("Failed to list files: {e}")),
        }
    }

    fn move_selection(&mut self, delta: i32) {
        if self.files.is_empty() {
            return;
        }
        let len = self.files.len() as i32;
        let mut idx = self.selected as i32 + delta;
        if idx < 0 {
            idx = 0;
        } else if idx >= len {
            idx = len - 1;
        }
        self.selected = idx as usize;
    }

    fn start_add(&mut self) {
        self.add_form = Some(AddFileForm::default());
    }

    fn submit_add(&mut self) {
        let Some(form) = self.add_form.clone() else { return };
        if form.source_path.trim().is_empty() || form.dest_name.trim().is_empty() {
            if let Some(f) = &mut self.add_form {
                f.error = Some("Both fields are required".to_string());
            }
            return;
        }
        let data = match std::fs::read(form.source_path.trim()) {
            Ok(d) => d,
            Err(e) => {
                if let Some(f) = &mut self.add_form {
                    f.error = Some(format!("Could not read source file: {e}"));
                }
                return;
            }
        };
        match self.vault.add_file(form.dest_name.trim(), &data) {
            Ok(()) => {
                log::log_event(&format!("file added to vault \"{}\": {}", self.name, form.dest_name.trim()));
                self.refresh_files();
                self.add_form = None;
                self.message = Some(format!("Added \"{}\"", form.dest_name.trim()));
            }
            Err(e) => {
                if let Some(f) = &mut self.add_form {
                    f.error = Some(e.to_string());
                }
            }
        }
    }

    fn delete_selected(&mut self) {
        let Some(file) = self.files.get(self.selected).cloned() else { return };
        match self.vault.delete_file(&file.name) {
            Ok(()) => {
                log::log_event(&format!("file deleted from vault \"{}\": {}", self.name, file.name));
                self.refresh_files();
                self.message = Some(format!("Deleted \"{}\"", file.name));
            }
            Err(e) => self.message = Some(e.to_string()),
        }
    }

    fn verify(&mut self) {
        match self.vault.verify_integrity() {
            Ok(()) => self.message = Some("Integrity check passed.".to_string()),
            Err(e) => self.message = Some(format!("Integrity check FAILED: {e}")),
        }
    }

    fn open_peers_view(&mut self) {
        let recipients = self.vault.list_recipients().unwrap_or_default();
        self.peers = Some(PeersView { recipients, selected: 0, mode: PeersMode::Browsing });
    }

    fn submit_grant(&mut self, input: &str) -> Result<(), String> {
        let invite = InviteCode::decode(input.trim()).map_err(|e| e.to_string())?;
        self.vault.grant_access(&invite.peer_id).map_err(|e| e.to_string())?;
        log::log_event(&format!(
            "granted access to {} on vault \"{}\"",
            invite.peer_id.fingerprint(),
            self.name
        ));
        Ok(())
    }

    fn submit_revoke(&mut self, target: &core::PeerId, password: &str) -> Result<(), String> {
        self.vault.revoke_access(&target.signing_public, password).map_err(|e| e.to_string())?;
        log::log_event(&format!(
            "revoked access from {} on vault \"{}\" (key rotated)",
            target.fingerprint(),
            self.name
        ));
        Ok(())
    }
}

pub enum Outcome {
    Continue,
    Lock,
}

pub fn handle_key(state: &mut UnlockedState, key: KeyEvent) -> Outcome {
    // Any interaction while unlocked resets the 30s inactivity timer.
    state.session.record_activity();

    if let Some(form) = &mut state.add_form {
        match key.code {
            KeyCode::Esc => {
                state.add_form = None;
            }
            KeyCode::Tab | KeyCode::Down | KeyCode::Up => {
                form.focus_dest = !form.focus_dest;
            }
            KeyCode::Enter => {
                if form.focus_dest {
                    state.submit_add();
                } else {
                    form.focus_dest = true;
                }
            }
            KeyCode::Backspace => {
                if form.focus_dest {
                    form.dest_name.pop();
                } else {
                    form.source_path.pop();
                }
            }
            KeyCode::Char(c) => {
                if form.focus_dest {
                    form.dest_name.push(c);
                } else {
                    form.source_path.push(c);
                }
            }
            _ => {}
        }
        return Outcome::Continue;
    }

    if state.peers.is_some() {
        handle_peers_key(state, key);
        return Outcome::Continue;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return Outcome::Lock,
        KeyCode::Up => state.move_selection(-1),
        KeyCode::Down => state.move_selection(1),
        KeyCode::Char('a') => state.start_add(),
        KeyCode::Char('d') => state.delete_selected(),
        KeyCode::Char('v') => state.verify(),
        KeyCode::Char('p') => state.open_peers_view(),
        _ => {}
    }
    Outcome::Continue
}

/// Handles one key press against the peer-management sub-view. Takes the
/// `PeersView` fully out of `state.peers` while working so that calling
/// admin-only `Vault` methods (which need `&mut state`) never conflicts
/// with holding a borrow into `state.peers` at the same time.
fn handle_peers_key(state: &mut UnlockedState, key: KeyEvent) {
    let Some(mut view) = state.peers.take() else { return };
    let mode = std::mem::replace(&mut view.mode, PeersMode::Browsing);

    let (new_mode, keep_open) = match mode {
        PeersMode::Browsing => match key.code {
            KeyCode::Esc | KeyCode::Char('q') => (PeersMode::Browsing, false),
            KeyCode::Up => {
                view.selected = view.selected.saturating_sub(1);
                (PeersMode::Browsing, true)
            }
            KeyCode::Down => {
                if view.selected + 1 < view.recipients.len() {
                    view.selected += 1;
                }
                (PeersMode::Browsing, true)
            }
            KeyCode::Char('g') => (PeersMode::Granting { input: String::new(), error: None }, true),
            KeyCode::Char('r') => {
                if let Some(target) = view.recipients.get(view.selected).map(|r| r.peer_id) {
                    (PeersMode::ConfirmRevoke { target, password: String::new(), error: None }, true)
                } else {
                    (PeersMode::Browsing, true)
                }
            }
            _ => (PeersMode::Browsing, true),
        },

        PeersMode::Granting { mut input, error } => match key.code {
            KeyCode::Esc => (PeersMode::Browsing, true),
            KeyCode::Backspace => {
                input.pop();
                (PeersMode::Granting { input, error }, true)
            }
            KeyCode::Char(c) => {
                input.push(c);
                (PeersMode::Granting { input, error }, true)
            }
            KeyCode::Enter => match state.submit_grant(&input) {
                Ok(()) => {
                    view.recipients = state.vault.list_recipients().unwrap_or_default();
                    (PeersMode::Browsing, true)
                }
                Err(e) => (PeersMode::Granting { input, error: Some(e) }, true),
            },
            _ => (PeersMode::Granting { input, error }, true),
        },

        PeersMode::ConfirmRevoke { target, mut password, error } => match key.code {
            KeyCode::Esc => (PeersMode::Browsing, true),
            KeyCode::Backspace => {
                password.pop();
                (PeersMode::ConfirmRevoke { target, password, error }, true)
            }
            KeyCode::Char(c) => {
                password.push(c);
                (PeersMode::ConfirmRevoke { target, password, error }, true)
            }
            KeyCode::Enter => match state.submit_revoke(&target, &password) {
                Ok(()) => {
                    view.recipients = state.vault.list_recipients().unwrap_or_default();
                    if view.selected >= view.recipients.len() {
                        view.selected = view.recipients.len().saturating_sub(1);
                    }
                    state.message = Some("Access revoked; vault key rotated.".to_string());
                    (PeersMode::Browsing, true)
                }
                Err(e) => (PeersMode::ConfirmRevoke { target, password: String::new(), error: Some(e) }, true),
            },
            _ => (PeersMode::ConfirmRevoke { target, password, error }, true),
        },
    };

    view.mode = new_mode;
    if keep_open {
        state.peers = Some(view);
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

pub fn render(frame: &mut Frame, area: Rect, state: &UnlockedState) {
    if let Some(view) = &state.peers {
        render_peers_view(frame, area, view);
        return;
    }

    if let Some(form) = &state.add_form {
        render_add_form(frame, area, form);
        return;
    }

    let layout = Layout::vertical([Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1)]);
    let [title_a, table_a, message_a] = area.layout(&layout);

    let title = Paragraph::new(Line::from(format!(
        "{}  ({} used of {})",
        state.name,
        format_bytes(state.vault.used_bytes()),
        format_bytes(state.vault.capacity_bytes())
    )));
    frame.render_widget(title, title_a);

    let header = Row::new(["Name", "Size", "Modified"]).style(Style::new().bold()).bottom_margin(1);
    let rows: Vec<Row> = state
        .files
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let style = if i == state.selected {
                Style::default().fg(Color::Rgb(255, 140, 0))
            } else {
                Style::default()
            };
            Row::new([f.name.clone(), format_bytes(f.size), f.modified_at.to_string()]).style(style)
        })
        .collect();
    let table = Table::new(rows, [Constraint::Length(30), Constraint::Length(12), Constraint::Length(16)]).header(header);
    frame.render_widget(table, table_a);

    if let Some(msg) = &state.message {
        let message = Paragraph::new(Line::from(msg.as_str()));
        frame.render_widget(message, message_a);
    }
}

fn render_add_form(frame: &mut Frame, area: Rect, form: &AddFileForm) {
    let layout = Layout::vertical([Constraint::Length(3), Constraint::Length(3), Constraint::Fill(1)]);
    let [source_a, dest_a, error_a] = area.layout(&layout);

    let source_block = Block::default()
        .borders(Borders::ALL)
        .title(" Source file path on disk ")
        .border_style(if form.focus_dest { Style::default() } else { Style::default().fg(Color::Rgb(255, 140, 0)) });
    frame.render_widget(Paragraph::new(Line::from(form.source_path.as_str())).block(source_block), source_a);

    let dest_block = Block::default()
        .borders(Borders::ALL)
        .title(" Name inside vault ")
        .border_style(if form.focus_dest { Style::default().fg(Color::Rgb(255, 140, 0)) } else { Style::default() });
    frame.render_widget(Paragraph::new(Line::from(form.dest_name.as_str())).block(dest_block), dest_a);

    if let Some(err) = &form.error {
        let error_line = Paragraph::new(Line::from(err.as_str())).style(Style::default().fg(Color::Red));
        frame.render_widget(error_line, error_a);
    }
}

fn render_peers_view(frame: &mut Frame, area: Rect, view: &PeersView) {
    match &view.mode {
        PeersMode::Browsing => {
            let layout = Layout::vertical([Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1)]);
            let [title_a, table_a, hint_a] = area.layout(&layout);

            frame.render_widget(Paragraph::new(Line::from("Granted peers")), title_a);

            let header = Row::new(["Fingerprint", "Granted at"]).style(Style::new().bold()).bottom_margin(1);
            let rows: Vec<Row> = view
                .recipients
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    let style = if i == view.selected {
                        Style::default().fg(Color::Rgb(255, 140, 0))
                    } else {
                        Style::default()
                    };
                    Row::new([r.peer_id.fingerprint(), r.granted_at.to_string()]).style(style)
                })
                .collect();
            let table = Table::new(rows, [Constraint::Length(20), Constraint::Length(16)]).header(header);
            frame.render_widget(table, table_a);

            let hint = Paragraph::new(Line::from("'g' grant new peer, 'r' revoke selected, Esc/'q' back"));
            frame.render_widget(hint, hint_a);
        }

        PeersMode::Granting { input, error } => {
            let layout = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]);
            let [field_a, error_a] = area.layout(&layout);

            let block = Block::default()
                .borders(Borders::ALL)
                .title(" Peer's invite code (from their `whoami`) ")
                .border_style(Style::default().fg(Color::Rgb(255, 140, 0)));
            frame.render_widget(Paragraph::new(Line::from(input.as_str())).block(block), field_a);

            if let Some(err) = error {
                let error_line = Paragraph::new(Line::from(err.as_str())).style(Style::default().fg(Color::Red));
                frame.render_widget(error_line, error_a);
            }
        }

        PeersMode::ConfirmRevoke { target, password, error } => {
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
    }
}
