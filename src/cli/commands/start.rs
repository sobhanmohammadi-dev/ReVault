use std::io;
use std::time::Duration;

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

                // Poll instead of blocking so the loop wakes up
                // periodically even with no input -- required to enforce
                // the 30s inactivity timeout on wall-clock time rather
                // than only re-checking it on the next key press.
                if event::poll(Duration::from_millis(200))? {
                    if let Some(key) = event::read()?.as_key_press_event() {
                        if handle_key(&mut app, key) {
                            break Ok(());
                        }
                    }
                }

                app.tick();
            }
        })
    }
}