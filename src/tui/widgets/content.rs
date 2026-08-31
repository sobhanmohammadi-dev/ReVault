use ratatui::{
    layout::{Alignment, Rect},
    widgets::{Block, Paragraph},
    Frame,
};

use crate::tui::tab::Tab;

pub fn render(frame: &mut Frame, area: Rect, selected_tab: Tab) {
    let text = match selected_tab {
        Tab::Vaults => {
            "Great terminal interfaces start with a single widget."
        }

        Tab::Network => {
            "Coming soon!"
        }

        Tab::Logs => {
            "Render boldly, style with purpose."
        }
    };

    let block = Paragraph::new(text)
        .alignment(Alignment::Center)
        .block(Block::bordered());

    frame.render_widget(block, area);
}