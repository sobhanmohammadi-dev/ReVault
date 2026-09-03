use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Tabs},
    Frame,
};

use crate::tui::tab::Tab;

pub fn render(frame: &mut Frame, area: Rect, selected_tab: Tab) {
    let titles = ["Vaults", "Network", "Logs", "Settings"];

    let tabs = Tabs::new(
        titles
            .into_iter()
            .map(Line::from)
            .collect::<Vec<_>>(),
    )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Revault "),
        )
        .select(selected_tab.index())
        .highlight_style(
            Style::default()
                .fg(Color::Rgb(255, 140, 0)),
        );

    frame.render_widget(tabs, area);
}