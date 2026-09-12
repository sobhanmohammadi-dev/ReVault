use ratatui::{
    layout::{Alignment, Rect},
    widgets::Paragraph,
    Frame,
};

use crate::tui::{app::App, tab::Tab};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    match app.selected_tab {
        Tab::Vaults => {
            app.vaults.render(frame, area);
        }

        Tab::Network => {
            let placeholder = Paragraph::new("Network features are coming in a future release.")
                .alignment(Alignment::Center);
            frame.render_widget(placeholder, area);
        }

        Tab::Logs => {
            crate::tui::widgets::logs::render(frame, area);
        }

        Tab::Settings => {
            crate::tui::widgets::settings::render(frame, area, &app.settings_ui, &app.settings);
        }
    }
}
