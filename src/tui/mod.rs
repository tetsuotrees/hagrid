pub mod app;
pub mod input;
pub mod ui;

use std::io;

use crossterm::event::{self, Event};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::cli;
use input::KeyAction;

struct TerminalCleanup;

impl Drop for TerminalCleanup {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = io::stdout().execute(LeaveAlternateScreen);
    }
}

/// Entry point for `hagrid tui`. Returns an exit code.
pub fn run() -> i32 {
    let (conn, _keys) = match cli::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };

    let mut app = app::App::new();
    app.load(&conn);

    if let Err(e) = run_tui(&mut app, &conn) {
        eprintln!("TUI error: {}", e);
        return 1;
    }

    0
}

fn run_tui(app: &mut app::App, conn: &rusqlite::Connection) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let _cleanup = TerminalCleanup;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    // Main loop
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        if let Event::Key(key) = event::read()? {
            // Only handle Press events (avoid double-handling on some terminals)
            if key.kind != crossterm::event::KeyEventKind::Press {
                continue;
            }

            match input::handle_key(app, key) {
                KeyAction::Quit => break,
                KeyAction::Refresh => {
                    app.load(conn);
                }
                KeyAction::EnterDetail => {
                    app.enter_detail(conn);
                }
                KeyAction::Redraw | KeyAction::None => {}
            }
        }
    }

    Ok(())
}
