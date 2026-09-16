use crossterm::event::{KeyCode, KeyEvent};

use crate::tui::app::App;
use crate::tui::tab::Tab;
use crate::tui::widgets::{network_tab, settings};

/// Handles one key press. Returns `true` when the application should quit.
pub fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    if !app.intercepts_quit() && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
        return true;
    }
    if !app.blocks_tab_switch() && key.code == KeyCode::Tab {
        app.next_tab();
        return false;
    }

    match app.selected_tab {
        Tab::Vaults => app.vaults.handle_key(key),
        Tab::Network => network_tab::handle_key(app, key),
        Tab::Settings => settings::handle_key(&mut app.settings_ui, &mut app.settings, key),
        Tab::Logs => {}
    }

    false
}
