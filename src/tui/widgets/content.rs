use ratatui::{
    layout::{Alignment, Rect},
    widgets::{Block, Paragraph},
    Frame,
};

use crate::tui::tab::Tab;

pub fn render(frame: &mut Frame, area: Rect, selected_tab: Tab) {
    let tab = match selected_tab {
        Tab::Vaults => {
            crate::tui::widgets::Vaults::table::render(frame, area)
        }

        Tab::Network => {
            crate::tui::widgets::Vaults::table::render(frame, area)
        }

        Tab::Logs => {
            crate::tui::widgets::Vaults::table::render(frame, area)
        }
        Tab::Settings => {
            crate::tui::widgets::Vaults::table::render(frame, area)
        }
    };
}