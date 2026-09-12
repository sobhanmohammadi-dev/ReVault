use crate::tui::settings::AppSettings;
use crate::tui::tab::Tab;
use crate::tui::widgets::settings::SettingsWidget;
use crate::tui::widgets::vaults;

pub struct App {
    pub selected_tab: Tab,
    pub vaults: vaults::App,
    pub settings: AppSettings,
    pub settings_ui: SettingsWidget,
}

impl App {
    pub fn new() -> Self {
        let settings = AppSettings::load();
        let vaults = vaults::App::new_with_dir(settings.vaults_dir.clone());
        let settings_ui = SettingsWidget::new(&settings);
        Self {
            selected_tab: Tab::Vaults,
            vaults,
            settings,
            settings_ui,
        }
    }

    pub fn next_tab(&mut self) {
        self.selected_tab = self.selected_tab.next();
    }

    /// True while a modal/detail interaction (a vault open, a form being
    /// edited) should capture input instead of the global tab/quit keys.
    pub fn blocks_global_nav(&self) -> bool {
        match self.selected_tab {
            Tab::Vaults => self.vaults.is_modal(),
            Tab::Settings => self.settings_ui.editing,
            Tab::Network | Tab::Logs => false,
        }
    }

    pub fn index(&self) -> usize {
        self.selected_tab.index()
    }

    /// Called every event-loop iteration, independent of key presses, so
    /// wall-clock-based behavior (the 30s inactivity timeout) is enforced
    /// even when the user hasn't pressed anything recently.
    pub fn tick(&mut self) {
        self.vaults.check_timeout();
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
