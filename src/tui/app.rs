use crate::tui::settings::AppSettings;
use crate::tui::tab::Tab;
use crate::tui::widgets::network_tab::{self, NetworkTabWidget};
use crate::tui::widgets::settings::SettingsWidget;
use crate::tui::widgets::vaults;

pub struct App {
    pub selected_tab: Tab,
    pub vaults: vaults::App,
    pub settings: AppSettings,
    pub settings_ui: SettingsWidget,
    pub network_ui: NetworkTabWidget,
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
            network_ui: NetworkTabWidget::default(),
        }
    }

    pub fn next_tab(&mut self) {
        self.selected_tab = self.selected_tab.next();
    }

    /// True whenever `q`/`Esc` should be handled locally (locking a
    /// vault, cancelling a form) rather than quitting the whole app.
    pub fn intercepts_quit(&self) -> bool {
        match self.selected_tab {
            Tab::Vaults => self.vaults.intercepts_quit(),
            Tab::Network => network_tab::is_modal(&self.network_ui),
            Tab::Settings => self.settings_ui.editing,
            Tab::Logs => false,
        }
    }

    /// True whenever `Tab` has a local meaning (moving between fields in
    /// a form) and shouldn't switch app tabs.
    pub fn blocks_tab_switch(&self) -> bool {
        match self.selected_tab {
            Tab::Vaults => self.vaults.blocks_tab_switch(),
            Tab::Network => network_tab::is_modal(&self.network_ui),
            Tab::Settings => self.settings_ui.editing,
            Tab::Logs => false,
        }
    }

    pub fn index(&self) -> usize {
        self.selected_tab.index()
    }

    /// Called every event-loop iteration, independent of key presses, so
    /// wall-clock-based behavior (the 30s inactivity timeout, and
    /// answering pending network sync requests for whichever vault is
    /// unlocked) is enforced even when the user hasn't pressed anything
    /// recently, and regardless of which tab is currently selected.
    pub fn tick(&mut self) {
        self.vaults.check_timeout();
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
