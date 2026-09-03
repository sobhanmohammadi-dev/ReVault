#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Vaults,
    Network,
    Logs,
    Settings
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Self::Vaults => Self::Network,
            Self::Network => Self::Logs,
            Self::Logs => Self::Vaults,
            Self::Settings => Self::Settings
        }
    }

    pub fn index(self) -> usize {
        match self {
            Self::Vaults => 0,
            Self::Network => 1,
            Self::Logs => 2,
            Self::Settings => 3
        }
    }
}