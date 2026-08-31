use ratatui::{
    layout::{Constraint, Layout},
    Frame,
};

use crate::tui::{
    app::App,
    widgets::{content, footer, tabs},
};

pub fn render(frame: &mut Frame, app: &App) {
    let layout = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
        .spacing(1);

    let [main, bottom] = frame.area().layout(&layout);

    footer::render(frame, bottom, app);
    render_main(frame, main, app);
}

fn render_main(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let layout = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
    ])
        .spacing(1);

    let [tabs_area, content_area] = area.layout(&layout);

    tabs::render(frame, tabs_area, app.selected_tab);
    content::render(frame, content_area, app.selected_tab);
}