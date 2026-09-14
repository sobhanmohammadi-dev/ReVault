use ratatui::{
    layout::Rect,
    widgets::Paragraph,
    Frame,
};

use crate::tui::{app::App, tab::Tab};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let blocking = app.blocks_global_nav();

    let text = match (blocking, app.selected_tab) {
        (false, _) => "Press 'q' to quit, '↹' to navigate tabs, '↵' to select.",

        (true, Tab::Vaults) => {
            "Press 'q'/Esc to go back, '⬇⬆' to navigate, '↵' to select, '+' new vault, 'a' add file, 'd' delete file, 'v' verify, 'p' peers, 'n' serve/stop."
        }

        (true, Tab::Network) => "Press 'q' to exit Network, '⬇⬆' to navigate networks.",

        (true, Tab::Logs) => "Press 'q' to exit Logs, '⬇⬆' to navigate logs.",

        (true, Tab::Settings) => "Press ↵ to save, Esc to cancel.",
    };

    let footer = Paragraph::new(text).centered();

    frame.render_widget(footer, area);
}
