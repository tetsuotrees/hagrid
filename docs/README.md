# Hagrid Documentation Index

This folder is the operational source of truth for planning, execution, and architecture.

## Read In This Order

1. [spec.md](spec.md): Product and technical scope for the current implementation line.
2. [threat-model.md](threat-model.md): Security boundaries and invariants.
3. [adr/README.md](adr/README.md): Architectural decisions and rationale.
4. [plan/post-v0.1-execution-plan.md](plan/post-v0.1-execution-plan.md): Cross-workstream plan from v0.1 to v0.2.

## Active Execution Docs

- [plan/post-v0.1-execution-plan.md](plan/post-v0.1-execution-plan.md): Current stream sequencing and acceptance criteria.
- [runbooks/05-notifications.md](runbooks/05-notifications.md): Step-by-step runbook for the next execution stream.
- [handoffs/dev-agent-05-notifications.md](handoffs/dev-agent-05-notifications.md): Dev-agent handoff packet for WS-8.
- [../CHANGELOG.md](../CHANGELOG.md): Release history and unreleased queue.
- [releases/v0.1.0.md](releases/v0.1.0.md): v0.1.0 release notes.

## Recently Completed Streams

- [runbooks/04-rotation.md](runbooks/04-rotation.md): WS-7 rotation workflow.
- [handoffs/dev-agent-04-rotation.md](handoffs/dev-agent-04-rotation.md): WS-7 delivery handoff.
- [runbooks/03-watch-mode.md](runbooks/03-watch-mode.md): WS-6 watch mode.
- [handoffs/dev-agent-03-watch.md](handoffs/dev-agent-03-watch.md): WS-6 delivery handoff.

## Agent Coordination Contract

- Any scope change updates `docs/spec.md` and, if architectural, one or more ADRs.
- Any milestone sequencing change updates `docs/plan/post-v0.1-execution-plan.md`.
- Any operations workflow change updates the relevant runbook under `docs/runbooks/`.
- Any delegated execution packet must live under `docs/handoffs/` and include acceptance criteria.

## Test Suite

`cargo test` runs tests across multiple compilation targets:

- **lib.rs** — unit tests (compiled once for the library crate)
- **main.rs** — the same unit tests compiled again for the binary crate
- **tests/*.rs** — integration test files (one binary per file)

Because Rust compiles unit tests into both `lib` and `bin` targets, `cargo test` reports more **test invocations** than there are **unique test functions**. For example, 22 unit tests appear twice (lib + bin = 44 invocations), plus integration tests.

When reporting test results, use the phrasing "`cargo test` passes with N test invocations across all targets" rather than "N tests". To count unique test functions, use `cargo test -- --list 2>/dev/null | grep -c ': test$'` on a single target.

## Evidence and Reporting

Every execution stream should produce:

- commands run (build, test, lint, release verification)
- artifacts produced (workflow files, changelog/release notes updates)
- pass/fail outcomes with explicit exit codes
- follow-up issues for deferred work
