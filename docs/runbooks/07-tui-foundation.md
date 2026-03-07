# Runbook 07: TUI Foundation (WS-10)

**Status: Ready**

## Purpose

Open the v0.3 line with a local-only, read-only terminal UI for browsing
Hagrid’s inventory. This stream should stabilize app structure, layout, and
navigation before any mutating workflows are considered.

## Baseline

- `origin/main` at `f7c50cd` (`Docs: fix v0.2.0 release metadata`)
- tag `v0.2.0` points to `f7c50cd`
- `cargo test` passes with 190 test invocations across all targets
- no TUI command or module exists yet

## Scope

In scope:

- add `hagrid tui`
- add a TUI app/state module that reads existing Hagrid data directly
- render a first read-only dashboard/list/detail flow over inventory data
- implement keyboard navigation, refresh, and quit behavior
- add tests for state transitions, loading, and safe rendering

Out of scope:

- mutating actions from the TUI (`group`, `ungroup`, `forget`, `rotate`, etc.)
- embedded watch mode or background event loops
- notification configuration or delivery from the TUI
- MCP server work
- secret value display or editing

## Required Outputs

1. `hagrid tui` command wired into the CLI.
2. New TUI module(s), e.g. `src/tui/`, for:
   - app state
   - layout/rendering
   - input handling
   - data loading from existing library code
3. Tests covering:
   - empty-state behavior
   - navigation/state transitions
   - detail selection
   - safe rendering (no secret values)
4. Docs updates:
   - `docs/spec.md`
   - `docs/runbooks/07-tui-foundation.md`
   - `docs/handoffs/dev-agent-07-tui-foundation.md`
   - ADR only if the final TUI architecture adds a durable architectural rule

## Implementation Guidance

Keep the first slice narrow:

- prefer read-only views over action-heavy flows
- reuse existing query/data structures where practical
- do not shell out to existing CLI commands from the TUI
- keep the layout usable on a standard terminal size
- make quitting and refresh obvious and deterministic

Suggested initial information architecture:

- summary/header with high-level counts
- primary list view for groups or references
- detail pane for the selected item
- status/help footer with keybindings

Exact layout is flexible as long as the first slice is stable and testable.

## Procedure

1. Re-verify the current baseline.

```bash
cargo build
cargo clippy --all-targets -- -D warnings
cargo test
```

2. Add command wiring.

- add `tui` to the CLI
- keep normal CLI behavior unchanged

3. Build the read-only TUI slice.

- define app state and selection model
- load existing inventory/group/suggestion data without spawning subprocesses
- render metadata only
- wire key handling for navigation, refresh, and quit

4. Add focused tests.

- state transition tests
- loading tests over temp-db fixtures where useful
- rendering/model tests ensuring secret values are not exposed

5. Update docs only after the behavior is settled.

6. Commit in focused chunks.

- commit A: TUI command, app state, rendering, tests
- commit B: docs/spec/runbook/handoff updates

7. Do not push unless explicitly requested.

## Acceptance Checklist

- [ ] `cargo build` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test` passes across all targets
- [ ] `hagrid tui` launches and exits cleanly
- [ ] the TUI is read-only in this stream
- [ ] the TUI renders metadata only and never displays secret values
- [ ] no network calls are introduced

## Failure Handling

- baseline verification fails:
  - fix the smallest blocking issue first
  - rerun the full verification set
- layout is too brittle or terminal-size dependent:
  - reduce scope to fewer panes/views rather than layering on complexity
- app state becomes tightly coupled to rendering:
  - refactor before adding more views; the first slice should leave a stable
    base for future TUI work

## Evidence to Return

- commit hashes
- exact verification command outcomes
- brief description of the shipped views and keybindings
- any deferred UX or interaction follow-ups
- whether the branch is ready to push
