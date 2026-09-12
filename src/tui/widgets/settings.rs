use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use std::path::PathBuf;

use crate::tui::log;
use crate::tui::settings::AppSettings;

pub struct SettingsWidget {
    pub editing: bool,
    pub buffer: String,
}

impl SettingsWidget {
    pub fn new(settings: &AppSettings) -> Self {
        SettingsWidget { editing: false, buffer: settings.vaults_dir.display().to_string() }
    }
}

pub fn handle_key(widget: &mut SettingsWidget, settings: &mut AppSettings, key: KeyEvent) {
    if widget.editing {
        match key.code {
            KeyCode::Esc => {
                widget.editing = false;
                widget.buffer = settings.vaults_dir.display().to_string();
            }
            KeyCode::Enter => {
                let trimmed = widget.buffer.trim();
                if !trimmed.is_empty() {
                    settings.vaults_dir = PathBuf::from(trimmed);
                    let _ = settings.save();
                    log::log_event("settings updated: vaults_dir changed");
                }
                widget.editing = false;
            }
            KeyCode::Backspace => {
                widget.buffer.pop();
            }
            KeyCode::Char(c) => {
                widget.buffer.push(c);
            }
            _ => {}
        }
    } else if key.code == KeyCode::Enter {
        widget.editing = true;
    }
}

pub fn render(frame: &mut Frame, area: Rect, widget: &SettingsWidget, settings: &AppSettings) {
    let layout = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]);
    let [field_a, hint_a] = area.layout(&layout);

    let value = if widget.editing { widget.buffer.as_str() } else { settings.vaults_dir.to_str().unwrap_or("") };
    let style = if widget.editing {
        Style::default().fg(Color::Rgb(255, 140, 0))
    } else {
        Style::default()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Vaults directory ")
        .border_style(style);
    frame.render_widget(Paragraph::new(Line::from(value)).block(block), field_a);

    let hint = if widget.editing {
        "Press ↵ to save, Esc to cancel."
    } else {
        "Press ↵ to edit the vaults directory."
    };
    frame.render_widget(Paragraph::new(Line::from(hint)), hint_a);
}
