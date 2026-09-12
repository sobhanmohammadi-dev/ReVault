use crossterm::event::{KeyCode, KeyEvent};

use crate::tui::app::App;
use crate::tui::tab::Tab;
use crate::tui::widgets::settings;

/// Handles one key press. Returns `true` when the application should quit.
pub fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    if !app.blocks_global_nav() {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Tab => {
                app.next_tab();
                return false;
            }
            _ => {}
        }
    }

    match app.selected_tab {
        Tab::Vaults => app.vaults.handle_key(key),
        Tab::Settings => settings::handle_key(&mut app.settings_ui, &mut app.settings, key),
        Tab::Network | Tab::Logs => {}
    }

    false
}
