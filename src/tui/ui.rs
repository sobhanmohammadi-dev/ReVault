use ratatui::{
    layout::{Constraint, Layout},
    Frame,
};
use ratatui::layout::Rect;
use ratatui::widgets::Block;
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

fn render_main(frame: &mut Frame, area: Rect, app: &App) {
    let layout = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
    ])
        .spacing(1);

    let [tabs_area, content_area] = area.layout(&layout);

    // Render tabs
    tabs::render(frame, tabs_area, app.selected_tab);

    // create and render content container
    let content_block = Block::bordered();
    frame.render_widget(&content_block, content_area);

    // Render content inside the border
    let inner_area = content_block.inner(content_area);
    content::render(frame, inner_area, app);
}