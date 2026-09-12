use crossterm::event::{KeyCode, KeyEvent};

use crate::tui::app::App;
use crate::tui::tab::Tab;

pub fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('q') if !app.locked => {
            return true;
        }

        KeyCode::Esc if !app.locked => {
            return true;
        }

        KeyCode::Tab if !app.locked => {
            app.next_tab();
        }

        KeyCode::Enter if !app.locked => {
            app.lock();
        }

        KeyCode::Char('q') | KeyCode::Esc if app.locked => {
            app.unlock();
        }
        
        KeyCode::Char('+') if app.selected_tab == Tab::Vaults => {
            app.vaults.create();
        }

        _ => {}
    }

    false
}