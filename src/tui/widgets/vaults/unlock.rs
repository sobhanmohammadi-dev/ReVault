use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

#[derive(Debug, Clone, Default)]
pub struct UnlockForm {
    pub password: String,
    pub error: Option<String>,
}

pub enum UnlockOutcome {
    Submit,
    Cancel,
}

pub fn handle_key(form: &mut UnlockForm, key: KeyEvent) -> Option<UnlockOutcome> {
    match key.code {
        KeyCode::Esc => return Some(UnlockOutcome::Cancel),
        KeyCode::Enter => return Some(UnlockOutcome::Submit),
        KeyCode::Backspace => {
            form.password.pop();
        }
        KeyCode::Char(c) => {
            form.password.push(c);
        }
        _ => {}
    }
    None
}

pub fn render(frame: &mut Frame, area: Rect, name: &str, form: &UnlockForm) {
    let layout = Layout::vertical([Constraint::Length(3), Constraint::Length(3), Constraint::Fill(1)]);
    let [label_a, pass_a, error_a] = area.layout(&layout);

    let label = Paragraph::new(Line::from(format!("Unlock \"{name}\""))).centered();
    frame.render_widget(label, label_a);

    let masked = "*".repeat(form.password.chars().count());
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Password ")
        .border_style(Style::default().fg(Color::Rgb(255, 140, 0)));
    let paragraph = Paragraph::new(Line::from(masked)).block(block);
    frame.render_widget(paragraph, pass_a);

    if let Some(err) = &form.error {
        let error_line = Paragraph::new(Line::from(err.as_str()))
            .style(Style::default().fg(Color::Red))
            .centered();
        frame.render_widget(error_line, error_a);
    }
}
