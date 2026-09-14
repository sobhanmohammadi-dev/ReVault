//! "Join a vault as a granted peer" form: paste an invite code (from
//! someone else's `whoami --listen`), connect, and pull down a local
//! replica.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

#[derive(Debug, Clone, Default)]
pub struct JoinForm {
    pub input: String,
    pub error: Option<String>,
}

pub enum JoinOutcome {
    Submit,
    Cancel,
}

pub fn handle_key(form: &mut JoinForm, key: KeyEvent) -> Option<JoinOutcome> {
    match key.code {
        KeyCode::Esc => return Some(JoinOutcome::Cancel),
        KeyCode::Enter => return Some(JoinOutcome::Submit),
        KeyCode::Backspace => {
            form.input.pop();
        }
        KeyCode::Char(c) => {
            form.input.push(c);
        }
        _ => {}
    }
    None
}

pub fn render(frame: &mut Frame, area: Rect, form: &JoinForm) {
    let layout = Layout::vertical([Constraint::Length(3), Constraint::Length(1), Constraint::Fill(1)]);
    let [field_a, hint_a, error_a] = area.layout(&layout);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Peer's invite code (must include an address, from their `whoami --listen`) ")
        .border_style(Style::default().fg(Color::Rgb(255, 140, 0)));
    frame.render_widget(Paragraph::new(Line::from(form.input.as_str())).block(block), field_a);

    let hint = Paragraph::new(Line::from("Connecting blocks the app briefly while the sync completes."));
    frame.render_widget(hint, hint_a);

    if let Some(err) = &form.error {
        let error_line = Paragraph::new(Line::from(err.as_str())).style(Style::default().fg(Color::Red));
        frame.render_widget(error_line, error_a);
    }
}
