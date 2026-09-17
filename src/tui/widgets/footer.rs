use ratatui::{layout::Rect, widgets::Paragraph, Frame};

use crate::tui::{app::App, tab::Tab};
use crate::tui::widgets::network_tab::NetworkTabMode;
use crate::tui::widgets::vaults::Mode as VaultsMode;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let text = match app.selected_tab {
        Tab::Vaults => vaults_hint(app),
        Tab::Network => network_hint(app),
        Tab::Settings if app.settings_ui.editing => "Press ↵ to save, Esc to cancel.",
        Tab::Settings => "Press 'q' to quit, '↹' to navigate tabs, '↵' to edit the vaults directory.",
        Tab::Logs => "Press 'q' to quit, '↹' to navigate tabs.",
    };

    let footer = Paragraph::new(text).centered();
    frame.render_widget(footer, area);
}

fn vaults_hint(app: &App) -> &'static str {
    match &app.vaults.mode {
        VaultsMode::Browsing => "Press 'q' to quit, '↹' to navigate tabs, '↵' to unlock, '+' new vault.",
        VaultsMode::Creating(_) => "Press ↵ to continue/submit, Esc to cancel, ↹/⬇⬆ to move between fields.",
        VaultsMode::Unlocking(..) => "Press ↵ to unlock, Esc to cancel.",
        VaultsMode::Unlocked(state) if state.add_form.is_some() || state.update_form.is_some() => {
            "Press ↵ to continue/submit, Esc to cancel, ↹/⬇⬆ to switch fields."
        }
        VaultsMode::Unlocked(state) if state.delete_confirm.is_some() => "Press 'y' to confirm delete, 'n'/Esc to cancel.",
        VaultsMode::Unlocked(_) => {
            "Press 'q' to lock, '↹' to switch tabs, '⬇⬆' to navigate, 'a' add, 'u' update, 'd' delete, 'v' verify."
        }
    }
}

fn network_hint(app: &App) -> &'static str {
    match &app.network_ui.mode {
        NetworkTabMode::Idle => {
            "Press 'q' to quit, '↹' to navigate tabs, 'j' join a vault, 'g' grant, 'r' revoke, 'n' serve/stop."
        }
        NetworkTabMode::Joining { .. } | NetworkTabMode::Granting { .. } | NetworkTabMode::ServePrompt { .. } => {
            "Press ↵ to submit, Esc to cancel."
        }
        NetworkTabMode::ConfirmRevoke { .. } => "Press ↵ to confirm revocation, Esc to cancel.",
    }
}
