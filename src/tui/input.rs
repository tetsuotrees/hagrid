use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::app::{App, View};

/// Handle a key event and update app state. Returns true if the terminal
/// needs to be redrawn (i.e., state changed).
pub fn handle_key(app: &mut App, key: KeyEvent) -> KeyAction {
    // Global quit: q or Ctrl-c
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.should_quit = true;
        return KeyAction::Quit;
    }

    match app.view {
        View::List => handle_list_key(app, key),
        View::Detail => handle_detail_key(app, key),
    }
}

/// What action the caller should take after handling a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAction {
    /// Nothing changed, no redraw needed.
    None,
    /// State changed, redraw.
    Redraw,
    /// User wants to quit.
    Quit,
    /// User wants to refresh data from disk.
    Refresh,
    /// User wants to enter detail view (needs db connection).
    EnterDetail,
}

fn handle_list_key(app: &mut App, key: KeyEvent) -> KeyAction {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            app.should_quit = true;
            KeyAction::Quit
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.move_down();
            KeyAction::Redraw
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.move_up();
            KeyAction::Redraw
        }
        KeyCode::Tab | KeyCode::BackTab => {
            app.toggle_section();
            KeyAction::Redraw
        }
        KeyCode::Enter => KeyAction::EnterDetail,
        KeyCode::Char('r') => KeyAction::Refresh,
        _ => KeyAction::None,
    }
}

fn handle_detail_key(app: &mut App, key: KeyEvent) -> KeyAction {
    match key.code {
        KeyCode::Char('q') => {
            app.should_quit = true;
            KeyAction::Quit
        }
        KeyCode::Esc | KeyCode::Backspace => {
            app.back_to_list();
            KeyAction::Redraw
        }
        KeyCode::Char('r') => KeyAction::Refresh,
        _ => KeyAction::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn key_with_mod(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn test_quit_q() {
        let mut app = App::new();
        let action = handle_key(&mut app, key(KeyCode::Char('q')));
        assert_eq!(action, KeyAction::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn test_quit_ctrl_c() {
        let mut app = App::new();
        let action = handle_key(&mut app, key_with_mod(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert_eq!(action, KeyAction::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn test_quit_esc_in_list() {
        let mut app = App::new();
        let action = handle_key(&mut app, key(KeyCode::Esc));
        assert_eq!(action, KeyAction::Quit);
    }

    #[test]
    fn test_navigate_down() {
        let mut app = App::new();
        app.group_items = vec![
            crate::tui::app::ListItem::Group {
                label: "a".into(),
                status: crate::index::models::GroupStatus::Synced,
                member_count: 1,
            },
            crate::tui::app::ListItem::Group {
                label: "b".into(),
                status: crate::index::models::GroupStatus::Synced,
                member_count: 2,
            },
        ];
        let action = handle_key(&mut app, key(KeyCode::Char('j')));
        assert_eq!(action, KeyAction::Redraw);
        assert_eq!(app.group_index, 1);
    }

    #[test]
    fn test_navigate_up() {
        let mut app = App::new();
        app.group_items = vec![
            crate::tui::app::ListItem::Group {
                label: "a".into(),
                status: crate::index::models::GroupStatus::Synced,
                member_count: 1,
            },
            crate::tui::app::ListItem::Group {
                label: "b".into(),
                status: crate::index::models::GroupStatus::Synced,
                member_count: 2,
            },
        ];
        app.group_index = 1;
        let action = handle_key(&mut app, key(KeyCode::Char('k')));
        assert_eq!(action, KeyAction::Redraw);
        assert_eq!(app.group_index, 0);
    }

    #[test]
    fn test_tab_toggles_section() {
        let mut app = App::new();
        let action = handle_key(&mut app, key(KeyCode::Tab));
        assert_eq!(action, KeyAction::Redraw);
        assert_eq!(app.section, crate::tui::app::ListSection::Ungrouped);
    }

    #[test]
    fn test_enter_requests_detail() {
        let mut app = App::new();
        let action = handle_key(&mut app, key(KeyCode::Enter));
        assert_eq!(action, KeyAction::EnterDetail);
    }

    #[test]
    fn test_refresh() {
        let mut app = App::new();
        let action = handle_key(&mut app, key(KeyCode::Char('r')));
        assert_eq!(action, KeyAction::Refresh);
    }

    #[test]
    fn test_backspace_in_detail_goes_back() {
        let mut app = App::new();
        app.view = View::Detail;
        app.detail = Some(crate::tui::app::DetailInfo::Group {
            label: "test".into(),
            status: crate::index::models::GroupStatus::Synced,
            member_count: 0,
            created_at: "2024-01-01".into(),
            members: vec![],
        });
        let action = handle_key(&mut app, key(KeyCode::Backspace));
        assert_eq!(action, KeyAction::Redraw);
        assert_eq!(app.view, View::List);
        assert!(app.detail.is_none());
    }

    #[test]
    fn test_esc_in_detail_goes_back() {
        let mut app = App::new();
        app.view = View::Detail;
        let action = handle_key(&mut app, key(KeyCode::Esc));
        assert_eq!(action, KeyAction::Redraw);
        assert_eq!(app.view, View::List);
    }

    #[test]
    fn test_unknown_key_is_noop() {
        let mut app = App::new();
        let action = handle_key(&mut app, key(KeyCode::Char('x')));
        assert_eq!(action, KeyAction::None);
    }

    #[test]
    fn test_arrow_keys() {
        let mut app = App::new();
        app.group_items = vec![
            crate::tui::app::ListItem::Group {
                label: "a".into(),
                status: crate::index::models::GroupStatus::Synced,
                member_count: 1,
            },
            crate::tui::app::ListItem::Group {
                label: "b".into(),
                status: crate::index::models::GroupStatus::Synced,
                member_count: 1,
            },
        ];

        let action = handle_key(&mut app, key(KeyCode::Down));
        assert_eq!(action, KeyAction::Redraw);
        assert_eq!(app.group_index, 1);

        let action = handle_key(&mut app, key(KeyCode::Up));
        assert_eq!(action, KeyAction::Redraw);
        assert_eq!(app.group_index, 0);
    }
}
