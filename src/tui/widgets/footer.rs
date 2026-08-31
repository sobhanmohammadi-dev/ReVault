use ratatui::{
    layout::Rect,
    widgets::Paragraph,
    Frame,
};

use crate::tui::{
    app::App,
    tab::Tab,
};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let text = match (app.locked, app.selected_tab) {
        (false, _) => {
            "Press 'q' to quit, '↹' to navigate tabs, '↵' to select tab."
        }

        (true, Tab::Vaults) => {
            "Press 'q' to exit Vaults, '⬇⬆' to navigate vaults, '+' to create a new Vault."
        }

        (true, Tab::Network) => {
            "Press 'q' to exit Network, '⬇⬆' to navigate networks."
        }

        (true, Tab::Logs) => {
            "Press 'q' to exit Logs, '⬇⬆' to navigate logs."
        }
    };

    let footer = Paragraph::new(text).centered();

    frame.render_widget(footer, area);
}