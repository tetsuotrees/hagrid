pub mod exact;
pub mod heuristic;

use crate::index::db;
use crate::index::models::Suggestion;
use crate::scan::engine::ScanDepth;

/// Generate all suggestions based on the current index state.
pub fn generate_suggestions(
    conn: &rusqlite::Connection,
    depth: ScanDepth,
) -> Result<Vec<Suggestion>, db::DbError> {
    let mut suggestions = Vec::new();

    // Always: exact fingerprint matches
    suggestions.extend(exact::suggest_exact_matches(conn)?);

    // Standard depth: heuristic matches
    if depth == ScanDepth::Standard {
        suggestions.extend(heuristic::suggest_heuristic_matches(conn)?);
    }

    // Store new suggestions in DB
    for s in &suggestions {
        db::insert_suggestion(conn, s)?;
    }

    Ok(suggestions)
}
