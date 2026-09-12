use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Description,
    Capacity,
    Password,
    Confirm,
}

impl Field {
    fn next(self) -> Self {
        match self {
            Field::Name => Field::Description,
            Field::Description => Field::Capacity,
            Field::Capacity => Field::Password,
            Field::Password => Field::Confirm,
            Field::Confirm => Field::Name,
        }
    }

    fn prev(self) -> Self {
        match self {
            Field::Name => Field::Confirm,
            Field::Description => Field::Name,
            Field::Capacity => Field::Description,
            Field::Password => Field::Capacity,
            Field::Confirm => Field::Password,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateForm {
    pub name: String,
    pub description: String,
    pub capacity: String,
    pub password: String,
    pub confirm: String,
    pub focus: Field,
    pub error: Option<String>,
}

impl Default for CreateForm {
    fn default() -> Self {
        CreateForm {
            name: String::new(),
            description: String::new(),
            capacity: "10 GB".to_string(),
            password: String::new(),
            confirm: String::new(),
            focus: Field::Name,
            error: None,
        }
    }
}

pub enum CreateOutcome {
    Submit,
    Cancel,
}

impl CreateForm {
    fn field_mut(&mut self) -> &mut String {
        match self.focus {
            Field::Name => &mut self.name,
            Field::Description => &mut self.description,
            Field::Capacity => &mut self.capacity,
            Field::Password => &mut self.password,
            Field::Confirm => &mut self.confirm,
        }
    }
}

/// Handles one key press against the create-vault form. Returns `Some` when
/// the form should be submitted or cancelled by the caller.
pub fn handle_key(form: &mut CreateForm, key: KeyEvent) -> Option<CreateOutcome> {
    match key.code {
        KeyCode::Esc => return Some(CreateOutcome::Cancel),
        KeyCode::Tab | KeyCode::Down => {
            form.focus = form.focus.next();
        }
        KeyCode::BackTab | KeyCode::Up => {
            form.focus = form.focus.prev();
        }
        KeyCode::Enter => {
            if form.focus == Field::Confirm {
                return Some(CreateOutcome::Submit);
            }
            form.focus = form.focus.next();
        }
        KeyCode::Backspace => {
            form.field_mut().pop();
        }
        KeyCode::Char(c) => {
            form.field_mut().push(c);
        }
        _ => {}
    }
    None
}

fn render_field(frame: &mut Frame, area: Rect, label: &str, value: &str, mask: bool, focused: bool) {
    let display_value = if mask {
        "*".repeat(value.chars().count())
    } else {
        value.to_string()
    };
    let style = if focused {
        Style::default().fg(Color::Rgb(255, 140, 0))
    } else {
        Style::default()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {label} "))
        .border_style(style);
    let paragraph = Paragraph::new(Line::from(display_value)).block(block);
    frame.render_widget(paragraph, area);
}

pub fn render(frame: &mut Frame, area: Rect, form: &CreateForm) {
    let layout = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Fill(1),
    ]);
    let [name_a, desc_a, cap_a, pass_a, confirm_a, error_a] = area.layout(&layout);

    render_field(frame, name_a, "Name", &form.name, false, form.focus == Field::Name);
    render_field(
        frame,
        desc_a,
        "Description",
        &form.description,
        false,
        form.focus == Field::Description,
    );
    render_field(
        frame,
        cap_a,
        "Capacity (e.g. 10 GB, 500 MB, 1 TB)",
        &form.capacity,
        false,
        form.focus == Field::Capacity,
    );
    render_field(
        frame,
        pass_a,
        "Password",
        &form.password,
        true,
        form.focus == Field::Password,
    );
    render_field(
        frame,
        confirm_a,
        "Confirm Password",
        &form.confirm,
        true,
        form.focus == Field::Confirm,
    );

    if let Some(err) = &form.error {
        let error_line = Paragraph::new(Line::from(err.as_str()))
            .style(Style::default().fg(Color::Red));
        frame.render_widget(error_line, error_a);
    }
}
