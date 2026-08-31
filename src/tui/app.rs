use crate::tui::tab::Tab;

pub struct App {
    pub selected_tab: Tab,
    pub locked: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            selected_tab: Tab::Vaults,
            locked: false,
        }
    }

    pub fn next_tab(&mut self) {
        self.selected_tab = self.selected_tab.next();
    }

    pub fn lock(&mut self) {
        self.locked = true;
    }

    pub fn unlock(&mut self) {
        self.locked = false;
    }
}