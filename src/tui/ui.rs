use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::app::{App, DetailInfo, ListSection, View};

/// Render the full TUI frame.
pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(5),   // body
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    draw_header(f, app, chunks[0]);

    if let Some(ref err) = app.error {
        draw_error(f, err, chunks[1]);
    } else {
        match app.view {
            View::List => draw_list(f, app, chunks[1]),
            View::Detail => draw_detail(f, app, chunks[1]),
        }
    }

    draw_footer(f, app, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.summary;
    let text = Line::from(vec![
        Span::styled(" hagrid ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw("| "),
        Span::styled(format!("{}", s.total_refs), Style::default().fg(Color::Cyan)),
        Span::raw(" refs  "),
        Span::styled(format!("{}", s.groups), Style::default().fg(Color::Green)),
        Span::raw(" groups  "),
        Span::styled(format!("{}", s.ungrouped), Style::default().fg(Color::White)),
        Span::raw(" ungrouped  "),
        Span::styled(format!("{}", s.pending_suggestions), Style::default().fg(Color::Magenta)),
        Span::raw(" suggestions  "),
        if s.unresolved_drift > 0 {
            Span::styled(
                format!("{} drift", s.unresolved_drift),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled("0 drift", Style::default().fg(Color::DarkGray))
        },
    ]);

    let block = Block::default().borders(Borders::BOTTOM);
    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, area);
}

fn draw_list(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Groups section
    draw_section(
        f,
        "Groups",
        &app.group_items,
        app.group_index,
        app.section == ListSection::Groups,
        chunks[0],
    );

    // Ungrouped section
    draw_section(
        f,
        "Ungrouped References",
        &app.ungrouped_items,
        app.ungrouped_index,
        app.section == ListSection::Ungrouped,
        chunks[1],
    );
}

fn draw_section(
    f: &mut Frame,
    title: &str,
    items: &[crate::tui::app::ListItem],
    selected: usize,
    is_active: bool,
    area: Rect,
) {
    let border_style = if is_active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let block = Block::default()
        .title(format!(" {} ({}) ", title, items.len()))
        .borders(Borders::ALL)
        .border_style(border_style);

    if items.is_empty() {
        let empty = Paragraph::new("  (empty)")
            .style(Style::default().fg(Color::DarkGray))
            .block(block);
        f.render_widget(empty, area);
        return;
    }

    let list_items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let (content, style) = format_list_item(item);
            let style = if i == selected && is_active {
                style.add_modifier(Modifier::REVERSED)
            } else {
                style
            };
            ListItem::new(content).style(style)
        })
        .collect();

    let list = List::new(list_items).block(block);
    f.render_widget(list, area);
}

fn format_list_item(item: &crate::tui::app::ListItem) -> (Line<'static>, Style) {
    match item {
        crate::tui::app::ListItem::Group {
            label,
            status,
            member_count,
        } => {
            let status_color = group_status_color(status);
            let line = Line::from(vec![
                Span::styled(
                    format!(" {} ", status),
                    Style::default().fg(status_color),
                ),
                Span::raw(format!("{} ", label)),
                Span::styled(
                    format!("({} members)", member_count),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            (line, Style::default())
        }
        crate::tui::app::ListItem::Reference {
            display_id,
            file_path,
            discriminator,
            provider,
            ..
        } => {
            let provider_str = provider
                .as_deref()
                .map(|p| format!("[{}] ", p))
                .unwrap_or_default();
            let line = Line::from(vec![
                Span::styled(
                    format!(" {} ", display_id),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(provider_str, Style::default().fg(Color::Yellow)),
                Span::raw(format!("{} ", shorten_path(file_path))),
                Span::styled(
                    discriminator.to_string(),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            (line, Style::default())
        }
    }
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Detail ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let detail = match &app.detail {
        Some(d) => d,
        None => {
            let p = Paragraph::new("  No item selected")
                .style(Style::default().fg(Color::DarkGray))
                .block(block);
            f.render_widget(p, area);
            return;
        }
    };

    let lines = format_detail(detail);
    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

fn format_detail(detail: &DetailInfo) -> Vec<Line<'static>> {
    match detail {
        DetailInfo::Group {
            label,
            status,
            member_count,
            created_at,
            members,
        } => {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("  Group: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(label.clone()),
                ]),
                Line::from(vec![
                    Span::styled("  Status: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        status.to_string(),
                        Style::default().fg(group_status_color(status)),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Members: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format!("{}", member_count)),
                ]),
                Line::from(vec![
                    Span::styled("  Created: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(created_at.clone()),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "  Members:",
                    Style::default().add_modifier(Modifier::BOLD),
                )),
            ];

            for m in members {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("    {} ", m.display_id),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(format!("{} ", shorten_path(&m.file_path))),
                    Span::styled(
                        m.discriminator.clone(),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        format!("[{}]", m.scan_status),
                        Style::default().fg(if m.scan_status == crate::index::models::ScanStatus::Present {
                            Color::Green
                        } else {
                            Color::Red
                        }),
                    ),
                ]));
            }

            lines
        }
        DetailInfo::Reference {
            display_id,
            file_path,
            kind,
            discriminator,
            provider,
            scan_status,
            first_seen,
            last_seen,
            last_changed,
            fingerprint_prefix,
        } => {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("  Reference: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(display_id.clone(), Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("  File: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(file_path.clone()),
                ]),
                Line::from(vec![
                    Span::styled("  Kind: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(kind.to_string()),
                ]),
                Line::from(vec![
                    Span::styled("  Key: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(discriminator.clone()),
                ]),
            ];

            if let Some(p) = provider {
                lines.push(Line::from(vec![
                    Span::styled("  Provider: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(p.clone(), Style::default().fg(Color::Yellow)),
                ]));
            }

            lines.extend_from_slice(&[
                Line::from(vec![
                    Span::styled("  Status: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        scan_status.to_string(),
                        Style::default().fg(if *scan_status == crate::index::models::ScanStatus::Present {
                            Color::Green
                        } else {
                            Color::Red
                        }),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Fingerprint: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(fingerprint_prefix.clone(), Style::default().fg(Color::DarkGray)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  First seen: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(first_seen.clone()),
                ]),
                Line::from(vec![
                    Span::styled("  Last seen: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(last_seen.clone()),
                ]),
                Line::from(vec![
                    Span::styled("  Last changed: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(last_changed.clone()),
                ]),
            ]);

            lines
        }
    }
}

fn draw_error(f: &mut Frame, error: &str, area: Rect) {
    let block = Block::default()
        .title(" Error ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let paragraph = Paragraph::new(format!("  {}", error))
        .style(Style::default().fg(Color::Red))
        .block(block);
    f.render_widget(paragraph, area);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let keys = match app.view {
        View::List => " q:quit  r:refresh  Tab:section  j/k:navigate  Enter:detail ",
        View::Detail => " q:quit  r:refresh  Backspace/Esc:back ",
    };
    let footer = Paragraph::new(Span::styled(
        keys,
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(footer, area);
}

fn group_status_color(status: &crate::index::models::GroupStatus) -> Color {
    match status {
        crate::index::models::GroupStatus::Synced => Color::Green,
        crate::index::models::GroupStatus::Drifted => Color::Red,
        crate::index::models::GroupStatus::Stale => Color::Yellow,
        crate::index::models::GroupStatus::Degraded => Color::Yellow,
        crate::index::models::GroupStatus::Empty => Color::DarkGray,
        crate::index::models::GroupStatus::Unknown => Color::DarkGray,
    }
}

/// Shorten a file path for display by using ~ for home dir.
fn shorten_path(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        if let Some(rest) = path.strip_prefix(home.to_str().unwrap_or("")) {
            return format!("~{}", rest);
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::models::GroupStatus;

    #[test]
    fn test_shorten_path_no_home() {
        let result = shorten_path("/etc/config");
        assert_eq!(result, "/etc/config");
    }

    #[test]
    fn test_group_status_colors() {
        assert_eq!(group_status_color(&GroupStatus::Synced), Color::Green);
        assert_eq!(group_status_color(&GroupStatus::Drifted), Color::Red);
        assert_eq!(group_status_color(&GroupStatus::Stale), Color::Yellow);
        assert_eq!(group_status_color(&GroupStatus::Empty), Color::DarkGray);
    }

    #[test]
    fn test_format_list_item_group() {
        let item = crate::tui::app::ListItem::Group {
            label: "my-api-keys".into(),
            status: GroupStatus::Synced,
            member_count: 3,
        };
        let (line, _style) = format_list_item(&item);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("my-api-keys"));
        assert!(text.contains("3 members"));
        assert!(text.contains("synced"));
    }

    #[test]
    fn test_format_list_item_reference() {
        let item = crate::tui::app::ListItem::Reference {
            display_id: "ref:abc123".into(),
            identity_key: "abc123full".into(),
            file_path: "/home/user/.env".into(),
            discriminator: "API_KEY".into(),
            kind: crate::index::models::LocationKind::EnvVar,
            provider: Some("openai".into()),
        };
        let (line, _style) = format_list_item(&item);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("ref:abc123"));
        assert!(text.contains("[openai]"));
        assert!(text.contains("API_KEY"));
        // Must not contain actual secret values
        assert!(!text.contains("sk-"));
    }

    #[test]
    fn test_format_detail_group() {
        let detail = DetailInfo::Group {
            label: "test-group".into(),
            status: GroupStatus::Drifted,
            member_count: 2,
            created_at: "2024-01-01 00:00".into(),
            members: vec![
                crate::tui::app::MemberDetail {
                    display_id: "ref:aaa111".into(),
                    file_path: "/app/.env".into(),
                    discriminator: "KEY".into(),
                    kind: crate::index::models::LocationKind::EnvVar,
                    scan_status: crate::index::models::ScanStatus::Present,
                },
            ],
        };
        let lines = format_detail(&detail);
        let all_text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.as_ref()))
            .collect();
        assert!(all_text.contains("test-group"));
        assert!(all_text.contains("drifted"));
        assert!(all_text.contains("ref:aaa111"));
    }

    #[test]
    fn test_format_detail_reference_no_secrets() {
        let detail = DetailInfo::Reference {
            display_id: "ref:def456".into(),
            file_path: "/home/user/.env".into(),
            kind: crate::index::models::LocationKind::EnvVar,
            discriminator: "STRIPE_KEY".into(),
            provider: Some("stripe".into()),
            scan_status: crate::index::models::ScanStatus::Present,
            first_seen: "2024-01-01 00:00".into(),
            last_seen: "2024-06-01 00:00".into(),
            last_changed: "2024-03-15 00:00".into(),
            fingerprint_prefix: "a1b2c3d4e5f6...".into(),
        };
        let lines = format_detail(&detail);
        let all_text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.as_ref()))
            .collect();
        assert!(all_text.contains("ref:def456"));
        assert!(all_text.contains("STRIPE_KEY"));
        assert!(all_text.contains("stripe"));
        assert!(all_text.contains("a1b2c3d4e5f6..."));
        // Must not contain any real secret value
        assert!(!all_text.contains("sk_live_"));
        assert!(!all_text.contains("sk_test_"));
    }
}
