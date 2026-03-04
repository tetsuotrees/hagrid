# Post-v0.1 Execution Plan

Status date: 2026-03-04

This plan coordinates work after the v0.1 implementation merge so release, CI hardening, and v0.2 kickoff happen in a controlled sequence.

## Objectives

- release v0.1.0 cleanly with clear public documentation
- establish non-optional quality gates in CI
- dogfood in real environments and convert observations into fixtures/issues
- close known cleanup items that reduce operator confusion
- start v0.2 from a stable base with explicit acceptance criteria

## Workstreams

### WS-1: v0.1 Release Hardening

Scope:

- add/maintain `CHANGELOG.md`
- draft release notes for `v0.1.0`
- create and verify tag/release artifacts

Deliverables:

- changelog entry for `0.1.0`
- release notes markdown
- signed/annotated git tag (`v0.1.0`) and GitHub release

Exit criteria:

- release notes reflect shipped scope and known limitations
- release tag resolves to the approved commit
- no open "must-fix-before-release" issues

### WS-2: CI/CD Quality Gates

Scope:

- add GitHub Actions CI for macOS
- run build/clippy/test as required checks
- document branch protection policy requirements

Deliverables:

- `.github/workflows/ci.yml`
- required status checks configured on `main`
- CI troubleshooting notes in runbook

Exit criteria:

- CI green on main branch head
- PR merge blocked when checks fail

### WS-3: Dogfooding and Signal Intake

Scope:

- run Hagrid against real local configs
- collect false positives/missed detections
- add fixtures/tests for reproducible findings

Deliverables:

- dogfooding log (issues or markdown summary)
- new/updated fixtures and tests for each confirmed defect

Exit criteria:

- at least one full real-world scan cycle documented
- each high-impact finding has either a fix or a tracked issue

### WS-4: Follow-up Cleanup

Scope:

- add integration test for hex-like group-label resolution paths
- clarify test counting language in docs/automation output
- tighten CLI behavior notes where ambiguity exists

Deliverables:

- new integration tests for `show` and `forget` disambiguation
- documentation update on test-invocation vs unique-test counting

Exit criteria:

- tests guard against regression in `deadbeef`-style labels
- docs no longer report inconsistent test totals

### WS-5: v0.2 Kickoff

Scope:

- policy engine and `hagrid audit`
- v0.2 implementation slicing and backlog ordering

Deliverables:

- v0.2 kickoff design note and task board
- first v0.2 PR scope defined (policy schema + audit command skeleton)

Exit criteria:

- first v0.2 PR merged with test coverage

## Sequence

1. WS-1 and WS-2 start immediately (parallel, with release cutoff gate in WS-1).
2. WS-3 starts once WS-2 CI is live (dogfooding findings must be reproducible in CI).
3. WS-4 runs continuously as defects emerge, but disambiguation test is prioritized in first pass.
4. WS-5 starts only after WS-1 through WS-3 exit criteria are met.

## Ownership and Handoff

- Dev Agent owns execution of WS-1 first.
- Review/Planning Agent validates acceptance criteria and updates this plan after each stream.
- Every stream must include a handoff doc under `docs/handoffs/` before work starts.

## Reporting Cadence

- End-of-stream summary:
  - changes made
  - verification commands and outcomes
  - open risks
  - next recommended stream

