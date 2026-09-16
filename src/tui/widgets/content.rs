use ratatui::{layout::Rect, Frame};

use crate::tui::{app::App, tab::Tab};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    match app.selected_tab {
        Tab::Vaults => {
            app.vaults.render(frame, area);
        }

        Tab::Network => {
            crate::tui::widgets::network_tab::render(frame, area, app);
        }

        Tab::Logs => {
            crate::tui::widgets::logs::render(frame, area);
        }

        Tab::Settings => {
            crate::tui::widgets::settings::render(frame, area, &app.settings_ui, &app.settings);
        }
    }
}
