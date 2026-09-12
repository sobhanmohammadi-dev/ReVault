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
            Self::Logs => Self::Settings,
            Self::Settings => Self::Vaults
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