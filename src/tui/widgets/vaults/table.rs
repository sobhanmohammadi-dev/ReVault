use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Row, Table};
use ratatui::Frame;

use super::VaultListing;

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

pub fn render(frame: &mut Frame, area: Rect, listing: &[VaultListing], selected: usize) {
    let header = Row::new(["Name", "Capacity", "Description"])
        .style(Style::new().bold())
        .bottom_margin(1);

    let rows: Vec<Row> = listing
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let style = if i == selected {
                Style::default().fg(Color::Rgb(255, 140, 0))
            } else {
                Style::default()
            };
            Row::new([v.name.clone(), format_bytes(v.capacity_bytes), v.description.clone()]).style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Length(20), Constraint::Length(10), Constraint::Fill(1)],
    )
    .header(header);

    frame.render_widget(table, area);
}
