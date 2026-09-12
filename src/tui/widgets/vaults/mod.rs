pub mod table;
pub mod create;

pub struct App {
    pub(crate) creating_vaultmode: Option<CreatingVaultmode>
}

#[derive(Clone)]
pub enum CreatingVaultmode {
    On,
    Off
}

impl App {
    pub fn new() -> Self {
        Self {
            creating_vaultmode: None,
        }
    }

    pub fn create(&mut self) {
        self.creating_vaultmode = Some(CreatingVaultmode::On)
    }
}