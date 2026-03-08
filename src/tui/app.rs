use crate::index::db;
use crate::index::fingerprint;
use crate::index::models::*;
use rusqlite::Connection;
use std::collections::HashMap;

/// Which view is currently active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum View {
    List,
    Detail,
}

/// Which section of the list is focused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListSection {
    Groups,
    Ungrouped,
}

/// A list item in the main view.
#[derive(Debug, Clone)]
pub enum ListItem {
    Group {
        label: String,
        status: GroupStatus,
        member_count: usize,
    },
    Reference {
        display_id: String,
        identity_key: String,
        file_path: String,
        discriminator: String,
        kind: LocationKind,
        provider: Option<String>,
    },
}

/// Detail information for a selected item.
#[derive(Debug, Clone)]
pub enum DetailInfo {
    Group {
        label: String,
        status: GroupStatus,
        member_count: usize,
        created_at: String,
        members: Vec<MemberDetail>,
    },
    Reference {
        display_id: String,
        file_path: String,
        kind: LocationKind,
        discriminator: String,
        provider: Option<String>,
        scan_status: ScanStatus,
        first_seen: String,
        last_seen: String,
        last_changed: String,
        fingerprint_prefix: String,
    },
}

/// Detail about a group member shown in group detail view.
#[derive(Debug, Clone)]
pub struct MemberDetail {
    pub display_id: String,
    pub file_path: String,
    pub discriminator: String,
    pub kind: LocationKind,
    pub scan_status: ScanStatus,
}

/// Summary counts for the header.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub total_refs: usize,
    pub groups: usize,
    pub ungrouped: usize,
    pub pending_suggestions: usize,
    pub unresolved_drift: usize,
}

/// Application state for the TUI.
pub struct App {
    pub view: View,
    pub section: ListSection,
    pub summary: Summary,
    pub group_items: Vec<ListItem>,
    pub ungrouped_items: Vec<ListItem>,
    pub group_index: usize,
    pub ungrouped_index: usize,
    pub detail: Option<DetailInfo>,
    pub should_quit: bool,
    pub error: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// Create an empty app with no data loaded.
    pub fn new() -> Self {
        Self {
            view: View::List,
            section: ListSection::Groups,
            summary: Summary::default(),
            group_items: Vec::new(),
            ungrouped_items: Vec::new(),
            group_index: 0,
            ungrouped_index: 0,
            detail: None,
            should_quit: false,
            error: None,
        }
    }

    /// Load all data from the database.
    pub fn load(&mut self, conn: &Connection) {
        self.error = None;

        // Load summary counts
        match load_summary(conn) {
            Ok(s) => self.summary = s,
            Err(e) => {
                self.error = Some(format!("Failed to load summary: {}", e));
                return;
            }
        }

        // Load list items
        match load_list_items(conn) {
            Ok((groups, ungrouped)) => {
                self.group_items = groups;
                self.ungrouped_items = ungrouped;
            }
            Err(e) => {
                self.error = Some(format!("Failed to load data: {}", e));
                return;
            }
        }

        // Clamp selection indices after reload
        self.clamp_indices();

        // If we're in detail view, reload the detail
        if self.view == View::Detail {
            self.load_detail(conn);
        }
    }

    /// Move selection up in the current list.
    pub fn move_up(&mut self) {
        match self.section {
            ListSection::Groups => {
                if self.group_index > 0 {
                    self.group_index -= 1;
                }
            }
            ListSection::Ungrouped => {
                if self.ungrouped_index > 0 {
                    self.ungrouped_index -= 1;
                }
            }
        }
    }

    /// Move selection down in the current list.
    pub fn move_down(&mut self) {
        match self.section {
            ListSection::Groups => {
                if !self.group_items.is_empty()
                    && self.group_index < self.group_items.len() - 1
                {
                    self.group_index += 1;
                }
            }
            ListSection::Ungrouped => {
                if !self.ungrouped_items.is_empty()
                    && self.ungrouped_index < self.ungrouped_items.len() - 1
                {
                    self.ungrouped_index += 1;
                }
            }
        }
    }

    /// Switch between Groups and Ungrouped sections.
    pub fn toggle_section(&mut self) {
        self.section = match self.section {
            ListSection::Groups => ListSection::Ungrouped,
            ListSection::Ungrouped => ListSection::Groups,
        };
    }

    /// Enter detail view for the currently selected item.
    pub fn enter_detail(&mut self, conn: &Connection) {
        self.load_detail(conn);
        if self.detail.is_some() {
            self.view = View::Detail;
        }
    }

    /// Go back to list view.
    pub fn back_to_list(&mut self) {
        self.view = View::List;
        self.detail = None;
    }

    fn load_detail(&mut self, conn: &Connection) {
        let item = match self.section {
            ListSection::Groups => self.group_items.get(self.group_index),
            ListSection::Ungrouped => self.ungrouped_items.get(self.ungrouped_index),
        };

        let item = match item {
            Some(i) => i.clone(),
            None => {
                self.detail = None;
                return;
            }
        };

        match item {
            ListItem::Group { label, .. } => {
                self.detail = load_group_detail(conn, &label).ok();
            }
            ListItem::Reference { identity_key, .. } => {
                self.detail = load_ref_detail(conn, &identity_key).ok();
            }
        }
    }

    fn clamp_indices(&mut self) {
        if self.group_items.is_empty() {
            self.group_index = 0;
        } else if self.group_index >= self.group_items.len() {
            self.group_index = self.group_items.len() - 1;
        }
        if self.ungrouped_items.is_empty() {
            self.ungrouped_index = 0;
        } else if self.ungrouped_index >= self.ungrouped_items.len() {
            self.ungrouped_index = self.ungrouped_items.len() - 1;
        }
    }

    /// Get the items for the currently active section.
    pub fn active_items(&self) -> &[ListItem] {
        match self.section {
            ListSection::Groups => &self.group_items,
            ListSection::Ungrouped => &self.ungrouped_items,
        }
    }

    /// Get the selection index for the currently active section.
    pub fn active_index(&self) -> usize {
        match self.section {
            ListSection::Groups => self.group_index,
            ListSection::Ungrouped => self.ungrouped_index,
        }
    }
}

fn load_summary(conn: &Connection) -> Result<Summary, String> {
    Ok(Summary {
        total_refs: db::count_references(conn).map_err(|e| e.to_string())?,
        groups: db::count_groups(conn).map_err(|e| e.to_string())?,
        ungrouped: db::count_ungrouped_references(conn).map_err(|e| e.to_string())?,
        pending_suggestions: db::count_pending_suggestions(conn).map_err(|e| e.to_string())?,
        unresolved_drift: db::count_unresolved_drift(conn).map_err(|e| e.to_string())?,
    })
}

fn load_list_items(conn: &Connection) -> Result<(Vec<ListItem>, Vec<ListItem>), String> {
    let groups = db::list_groups(conn).map_err(|e| e.to_string())?;
    let refs = db::list_references(conn).map_err(|e| e.to_string())?;

    // Build display IDs
    let all_keys: Vec<&str> = refs.iter().map(|r| r.identity_key.as_str()).collect();

    // Build set of grouped identity keys
    let grouped_keys: std::collections::HashSet<&str> = groups
        .iter()
        .flat_map(|g| g.members.iter().map(|m| m.as_str()))
        .collect();

    let group_items: Vec<ListItem> = groups
        .iter()
        .map(|g| ListItem::Group {
            label: g.label.clone(),
            status: g.status.clone(),
            member_count: g.members.len(),
        })
        .collect();

    let ungrouped_items: Vec<ListItem> = refs
        .iter()
        .filter(|r| r.scan_status == ScanStatus::Present && !grouped_keys.contains(r.identity_key.as_str()))
        .map(|r| ListItem::Reference {
            display_id: fingerprint::display_id(&r.identity_key, &all_keys),
            identity_key: r.identity_key.clone(),
            file_path: r.file_path.clone(),
            discriminator: r.location.discriminator.clone(),
            kind: r.location.kind.clone(),
            provider: r.provider_pattern.clone(),
        })
        .collect();

    Ok((group_items, ungrouped_items))
}

fn load_group_detail(conn: &Connection, label: &str) -> Result<DetailInfo, String> {
    let group = db::get_group_by_label(conn, label)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("group '{}' not found", label))?;

    let refs = db::list_references(conn).map_err(|e| e.to_string())?;
    let all_keys: Vec<&str> = refs.iter().map(|r| r.identity_key.as_str()).collect();
    let ref_map: HashMap<&str, &SecretReference> =
        refs.iter().map(|r| (r.identity_key.as_str(), r)).collect();

    let members: Vec<MemberDetail> = group
        .members
        .iter()
        .filter_map(|m| {
            ref_map.get(m.as_str()).map(|r| MemberDetail {
                display_id: fingerprint::display_id(&r.identity_key, &all_keys),
                file_path: r.file_path.clone(),
                discriminator: r.location.discriminator.clone(),
                kind: r.location.kind.clone(),
                scan_status: r.scan_status.clone(),
            })
        })
        .collect();

    Ok(DetailInfo::Group {
        label: group.label,
        status: group.status,
        member_count: group.members.len(),
        created_at: group.created_at.format("%Y-%m-%d %H:%M").to_string(),
        members,
    })
}

fn load_ref_detail(conn: &Connection, identity_key: &str) -> Result<DetailInfo, String> {
    let r = db::get_reference(conn, identity_key)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("reference '{}' not found", identity_key))?;

    let refs = db::list_references(conn).map_err(|e| e.to_string())?;
    let all_keys: Vec<&str> = refs.iter().map(|r| r.identity_key.as_str()).collect();

    Ok(DetailInfo::Reference {
        display_id: fingerprint::display_id(&r.identity_key, &all_keys),
        file_path: r.file_path,
        kind: r.location.kind,
        discriminator: r.location.discriminator,
        provider: r.provider_pattern,
        scan_status: r.scan_status,
        first_seen: r.first_seen.format("%Y-%m-%d %H:%M").to_string(),
        last_seen: r.last_seen.format("%Y-%m-%d %H:%M").to_string(),
        last_changed: r.last_changed.format("%Y-%m-%d %H:%M").to_string(),
        fingerprint_prefix: if r.fingerprint.len() >= 12 {
            format!("{}...", &r.fingerprint[..12])
        } else {
            format!("{}...", &r.fingerprint)
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_app_is_empty() {
        let app = App::new();
        assert_eq!(app.view, View::List);
        assert_eq!(app.section, ListSection::Groups);
        assert!(app.group_items.is_empty());
        assert!(app.ungrouped_items.is_empty());
        assert_eq!(app.group_index, 0);
        assert_eq!(app.ungrouped_index, 0);
        assert!(app.detail.is_none());
        assert!(!app.should_quit);
        assert!(app.error.is_none());
    }

    #[test]
    fn test_toggle_section() {
        let mut app = App::new();
        assert_eq!(app.section, ListSection::Groups);
        app.toggle_section();
        assert_eq!(app.section, ListSection::Ungrouped);
        app.toggle_section();
        assert_eq!(app.section, ListSection::Groups);
    }

    #[test]
    fn test_move_down_empty() {
        let mut app = App::new();
        app.move_down();
        assert_eq!(app.group_index, 0);
    }

    #[test]
    fn test_move_up_at_zero() {
        let mut app = App::new();
        app.move_up();
        assert_eq!(app.group_index, 0);
    }

    #[test]
    fn test_move_navigation_with_items() {
        let mut app = App::new();
        app.group_items = vec![
            ListItem::Group {
                label: "a".into(),
                status: GroupStatus::Synced,
                member_count: 2,
            },
            ListItem::Group {
                label: "b".into(),
                status: GroupStatus::Drifted,
                member_count: 3,
            },
            ListItem::Group {
                label: "c".into(),
                status: GroupStatus::Synced,
                member_count: 1,
            },
        ];

        assert_eq!(app.group_index, 0);
        app.move_down();
        assert_eq!(app.group_index, 1);
        app.move_down();
        assert_eq!(app.group_index, 2);
        app.move_down(); // at end, stays
        assert_eq!(app.group_index, 2);
        app.move_up();
        assert_eq!(app.group_index, 1);
    }

    #[test]
    fn test_back_to_list() {
        let mut app = App::new();
        app.view = View::Detail;
        app.detail = Some(DetailInfo::Group {
            label: "test".into(),
            status: GroupStatus::Synced,
            member_count: 0,
            created_at: "2024-01-01".into(),
            members: vec![],
        });
        app.back_to_list();
        assert_eq!(app.view, View::List);
        assert!(app.detail.is_none());
    }

    #[test]
    fn test_clamp_indices() {
        let mut app = App::new();
        app.group_index = 10;
        app.ungrouped_index = 5;
        app.group_items = vec![ListItem::Group {
            label: "a".into(),
            status: GroupStatus::Synced,
            member_count: 1,
        }];
        app.clamp_indices();
        assert_eq!(app.group_index, 0);
        assert_eq!(app.ungrouped_index, 0);
    }

    #[test]
    fn test_active_items_and_index() {
        let mut app = App::new();
        app.group_items = vec![ListItem::Group {
            label: "g".into(),
            status: GroupStatus::Synced,
            member_count: 1,
        }];
        app.ungrouped_items = vec![ListItem::Reference {
            display_id: "ref:abc123".into(),
            identity_key: "abc123".into(),
            file_path: "/test".into(),
            discriminator: "KEY".into(),
            kind: LocationKind::EnvVar,
            provider: None,
        }];

        assert_eq!(app.active_items().len(), 1);
        assert_eq!(app.active_index(), 0);

        app.toggle_section();
        assert_eq!(app.active_items().len(), 1);
        assert_eq!(app.active_index(), 0);
    }

    #[test]
    fn test_detail_info_no_secret_values() {
        // Verify that DetailInfo variants don't carry secret values
        let detail = DetailInfo::Reference {
            display_id: "ref:abc123".into(),
            file_path: "/home/user/.env".into(),
            kind: LocationKind::EnvVar,
            discriminator: "API_KEY".into(),
            provider: Some("openai".into()),
            scan_status: ScanStatus::Present,
            first_seen: "2024-01-01 00:00".into(),
            last_seen: "2024-01-02 00:00".into(),
            last_changed: "2024-01-01 00:00".into(),
            fingerprint_prefix: "a1b2c3d4e5f6...".into(),
        };
        // The detail should contain metadata only - no field named "value",
        // "secret", or similar that would hold the actual secret content.
        match detail {
            DetailInfo::Reference {
                display_id,
                file_path,
                discriminator,
                fingerprint_prefix,
                ..
            } => {
                assert!(!display_id.is_empty());
                assert!(!file_path.is_empty());
                assert!(!discriminator.is_empty());
                // Fingerprint prefix should be truncated, not the full hash
                assert!(fingerprint_prefix.ends_with("..."));
            }
            _ => panic!("expected Reference detail"),
        }
    }
}
