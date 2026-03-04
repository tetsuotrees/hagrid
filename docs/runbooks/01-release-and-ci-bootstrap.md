# Runbook 01: Release and CI Bootstrap

Owner: Dev Agent  
Phase: First execution stream after v0.1 implementation

## Purpose

Ship `v0.1.0` with clear release metadata and enforce CI quality gates on `main`.

## Preconditions

- working tree clean
- baseline verification passes locally:
  - `cargo build`
  - `cargo clippy --all-targets`
  - `cargo test`
- GitHub repo access for Actions and release operations

## Inputs

- implementation commit on `main` approved for release
- current docs (`README.md`, `docs/spec.md`, ADRs)

## Outputs

- `CHANGELOG.md` updated with `0.1.0` entry
- release notes doc (recommended: `docs/releases/v0.1.0.md`)
- CI workflow at `.github/workflows/ci.yml`
- pushed tag `v0.1.0` and published GitHub release

## Procedure

1. Re-verify release candidate

```bash
cargo build
cargo clippy --all-targets
cargo test
```

2. Prepare release documentation

- add `CHANGELOG.md` if missing
- add `0.1.0` section with:
  - shipped commands/features
  - security model highlights
  - known limitations (macOS-only, no v0.2 features yet)
- create release notes markdown with upgrade and verification notes

3. Add CI workflow

- create `.github/workflows/ci.yml` with:
  - trigger: push + pull_request on `main`
  - runner: `macos-latest`
  - steps:
    - checkout
    - rust toolchain setup
    - `cargo build`
    - `cargo clippy --all-targets -- -D warnings`
    - `cargo test`

4. Validate workflow locally where possible

- dry-run command set locally
- ensure no additional system dependencies are required for test execution

5. Commit and push

```bash
git add CHANGELOG.md docs/releases/v0.1.0.md .github/workflows/ci.yml
git commit -m "Add v0.1.0 release docs and CI quality gates"
git push origin main
```

6. Configure branch protections (if not already set)

- require CI workflow status checks before merge
- block direct merges that bypass checks where repository policy permits

7. Tag and publish release

```bash
git tag -a v0.1.0 -m "Hagrid v0.1.0"
git push origin v0.1.0
```

- create GitHub release from tag and attach release notes

## Acceptance Checklist

- [ ] CI workflow exists and runs on PRs to `main`
- [ ] changelog and release notes are committed
- [ ] `v0.1.0` tag points to intended commit
- [ ] GitHub release published
- [ ] post-release verification commands still pass

## Failure Handling

- CI fails after push:
  - fix in follow-up commit to `main`
  - do not publish release until required checks pass
- release docs mismatch:
  - patch docs immediately and regenerate release notes
- wrong tag target:
  - delete local/remote tag and recreate on correct commit before publishing

## Evidence to Include in Handoff Back

- commit hash(es)
- CI run URL(s)
- tag hash and release URL
- output summary for build/clippy/test

