use std::io;

use crossterm::event;

use crate::tui::{
    app::App,
    event::handle_key,
    ui,
};

pub struct Start;

impl Start {
    pub fn execute() -> io::Result<()> {
        let mut app = App::new();

        ratatui::run(|terminal| {
            loop {
                terminal.draw(|frame| {
                    ui::render(frame, &app);
                })?;

                if let Some(key) = event::read()?.as_key_press_event() {
                    if handle_key(&mut app, key) {
                        break Ok(());
                    }
                }
            }
        })
    }
}