//! Unlocked-vault file browser: list files, add/update/delete/verify,
//! feeds the 30s inactivity session.
//!
//! This module is deliberately vault/file-only. Peer management and
//! network serving live in `tui::widgets::network_tab` instead -- the
//! only thing this module keeps that's network-adjacent is the *live
//! serving session* itself (`network: Option<network_tab::NetworkSession>`),
//! because its lifecycle has to be tied to this specific vault being
//! open (serving must stop when the vault locks).

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
use crate::tui::log;
use crate::tui::widgets::network_tab::NetworkSession;

#[derive(Debug, Clone, Default)]
pub struct AddFileForm {
    pub source_path: String,
    pub dest_name: String,
    pub focus_dest: bool,
    pub error: Option<String>,
}

/// Replaces the contents of the currently *selected* file -- unlike
/// `AddFileForm`, there's no name field: the destination is whichever
/// file was selected when `u` was pressed.
#[derive(Debug, Clone, Default)]
pub struct UpdateFileForm {
    pub source_path: String,
    pub error: Option<String>,
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
    pub update_form: Option<UpdateFileForm>,
    /// Set to the selected file's name while a "really delete this?"
    /// confirmation is pending -- deletion is irreversible (the blocks
    /// are freed immediately), so it doesn't fire on a single keypress.
    pub delete_confirm: Option<String>,
    /// A live serving session, if this vault is currently being served
    /// to peers -- started/stopped from the Network tab, but owned here
    /// so it's torn down automatically when this vault locks.
    pub network: Option<NetworkSession>,
    /// Byte copy of this device's local identity, kept around only to
    /// hand to a freshly started `NetworkBridge` (which needs its own
    /// owned `Identity`, reconstructed from these bytes on its own
    /// thread -- see `NetworkBridge::start` for why).
    pub local_identity_bytes: [u8; 64],
}

impl UnlockedState {
    pub fn new(vault: core::Vault, path: PathBuf, name: String, local_identity_bytes: [u8; 64]) -> Self {
        let mut state = UnlockedState {
            vault,
            path,
            name,
            files: Vec::new(),
            selected: 0,
            session: Session::new(),
            message: None,
            add_form: None,
            update_form: None,
            delete_confirm: None,
            network: None,
            local_identity_bytes,
        };
        state.refresh_files();
        state
    }

    pub fn refresh_files(&mut self) {
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

    fn start_update(&mut self) {
        if self.files.get(self.selected).is_some() {
            self.update_form = Some(UpdateFileForm::default());
        }
    }

    fn request_delete(&mut self) {
        if let Some(file) = self.files.get(self.selected) {
            self.delete_confirm = Some(file.name.clone());
        }
    }

    /// If a serving session is active, records the patch this mutation
    /// just produced into its journal so reconnecting peers can get an
    /// incremental sync instead of a full resync.
    fn record_patch_if_serving(&mut self, seq_before: u64) {
        if self.network.is_some() {
            let ranges = self.vault.take_change_log();
            if let Some(net) = &mut self.network {
                net.journal.record(seq_before, ranges);
            }
        }
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
        let (seq_before, _) = self.vault.chain_state();
        match self.vault.add_file(form.dest_name.trim(), &data) {
            Ok(()) => {
                log::log_event(&format!("file added to vault \"{}\": {}", self.name, form.dest_name.trim()));
                self.record_patch_if_serving(seq_before);
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

    fn submit_update(&mut self) {
        let Some(form) = self.update_form.clone() else { return };
        let Some(target_name) = self.files.get(self.selected).map(|f| f.name.clone()) else {
            self.update_form = None;
            return;
        };
        if form.source_path.trim().is_empty() {
            if let Some(f) = &mut self.update_form {
                f.error = Some("A source path is required".to_string());
            }
            return;
        }
        let data = match std::fs::read(form.source_path.trim()) {
            Ok(d) => d,
            Err(e) => {
                if let Some(f) = &mut self.update_form {
                    f.error = Some(format!("Could not read source file: {e}"));
                }
                return;
            }
        };
        let (seq_before, _) = self.vault.chain_state();
        match self.vault.update_file(&target_name, &data) {
            Ok(()) => {
                log::log_event(&format!("file updated in vault \"{}\": {target_name}", self.name));
                self.record_patch_if_serving(seq_before);
                self.refresh_files();
                self.update_form = None;
                self.message = Some(format!("Updated \"{target_name}\""));
            }
            Err(e) => {
                if let Some(f) = &mut self.update_form {
                    f.error = Some(e.to_string());
                }
            }
        }
    }

    fn confirm_delete(&mut self) {
        let Some(name) = self.delete_confirm.take() else { return };
        let (seq_before, _) = self.vault.chain_state();
        match self.vault.delete_file(&name) {
            Ok(()) => {
                log::log_event(&format!("file deleted from vault \"{}\": {name}", self.name));
                self.record_patch_if_serving(seq_before);
                self.refresh_files();
                self.message = Some(format!("Deleted \"{name}\""));
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

    if let Some(form) = &mut state.update_form {
        match key.code {
            KeyCode::Esc => {
                state.update_form = None;
            }
            KeyCode::Enter => state.submit_update(),
            KeyCode::Backspace => {
                form.source_path.pop();
            }
            KeyCode::Char(c) => {
                form.source_path.push(c);
            }
            _ => {}
        }
        return Outcome::Continue;
    }

    if state.delete_confirm.is_some() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => state.confirm_delete(),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => state.delete_confirm = None,
            _ => {}
        }
        return Outcome::Continue;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return Outcome::Lock,
        KeyCode::Up => state.move_selection(-1),
        KeyCode::Down => state.move_selection(1),
        KeyCode::Char('a') => state.start_add(),
        KeyCode::Char('u') => state.start_update(),
        KeyCode::Char('d') => state.request_delete(),
        KeyCode::Char('v') => state.verify(),
        _ => {}
    }
    Outcome::Continue
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
    if let Some(form) = &state.add_form {
        render_add_form(frame, area, form);
        return;
    }

    if let Some(form) = &state.update_form {
        let target = state.files.get(state.selected).map(|f| f.name.as_str()).unwrap_or("?");
        render_update_form(frame, area, target, form);
        return;
    }

    if let Some(name) = &state.delete_confirm {
        render_delete_confirm(frame, area, name);
        return;
    }

    let layout = Layout::vertical([Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1)]);
    let [title_a, table_a, message_a] = area.layout(&layout);

    let serving_suffix = match &state.network {
        Some(net) => format!("  [serving on :{}]", net.bridge.listen_addr.port()),
        None => String::new(),
    };
    let title = Paragraph::new(Line::from(format!(
        "{}  ({} used of {}){}",
        state.name,
        format_bytes(state.vault.used_bytes()),
        format_bytes(state.vault.capacity_bytes()),
        serving_suffix
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

fn render_update_form(frame: &mut Frame, area: Rect, target_name: &str, form: &UpdateFileForm) {
    let layout = Layout::vertical([Constraint::Length(1), Constraint::Length(3), Constraint::Fill(1)]);
    let [label_a, field_a, error_a] = area.layout(&layout);

    let label = Paragraph::new(Line::from(format!("Replace contents of \"{target_name}\"")));
    frame.render_widget(label, label_a);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" New content: source file path on disk ")
        .border_style(Style::default().fg(Color::Rgb(255, 140, 0)));
    frame.render_widget(Paragraph::new(Line::from(form.source_path.as_str())).block(block), field_a);

    if let Some(err) = &form.error {
        let error_line = Paragraph::new(Line::from(err.as_str())).style(Style::default().fg(Color::Red));
        frame.render_widget(error_line, error_a);
    }
}

fn render_delete_confirm(frame: &mut Frame, area: Rect, name: &str) {
    let layout = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]);
    let [label_a, _rest] = area.layout(&layout);

    let label = Paragraph::new(Line::from(format!("Delete \"{name}\"? This cannot be undone. (y/n)")))
        .style(Style::default().fg(Color::Red));
    frame.render_widget(label, label_a);
}
