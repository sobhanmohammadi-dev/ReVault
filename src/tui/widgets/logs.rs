use ratatui::{
    layout::Rect,
    text::Line,
    widgets::Paragraph,
    Frame,
};

use crate::tui::log;

/// Renders the most recent application log lines that fit in `area`. This
/// is the plain operational log (vault created/unlocked/locked/file
/// added/deleted, etc.) -- distinct from a vault's internal, tamper-evident
/// hash chain.
pub fn render(frame: &mut Frame, area: Rect) {
    let capacity = area.height.max(1) as usize;
    let lines: Vec<Line> = log::read_recent(capacity).into_iter().map(Line::from).collect();
    frame.render_widget(Paragraph::new(lines), area);
}
