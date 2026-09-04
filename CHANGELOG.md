# Changelog

All notable changes to Admissible are recorded here. The project follows
Semantic Versioning for its coordinated public distributions.

## [Unreleased]

No changes yet.

## [0.8.1] - 04/09/2026

### Fixed

- Anchor the clock-skew freshness guard at the decision clock (`decided_at`)
  rather than the wall clock or a check's start time, across `admissible-core`,
  `admissible-ready`, and `admissible-trust`: evidence or a review dated more
  than the allowed skew beyond the decision clock is refused as future-dated,
  and the freshness window follows the decision, not `now`.

## [0.8.0] - 30/08/2026

The first formal public baseline for the coordinated Admissible distributions.

### Added

- Four coordinated distributions: `admissible-core`, `admissible-ready`,
  `admissible-trust`, and the compatibility umbrella `admissible`.
- Cross-process Ready-to-Trust handoff, isolated-install checks, reproducible
  artifact gates, package membership checks, and architecture sabotage tests.
- Public licensing, citation, security, contribution, release, community-health,
  and third-party notice documents.

### Changed

- Candidate execution and trusted finalization are separate package, process,
  credential, persistence, and command authorities.
- Software and repository documentation use Apache-2.0. Research manuscripts
  and generated research PDFs use CC BY 4.0.
- Release build backends are pinned to `setuptools==83.0.0`.

### Fixed

- Python 3.10 compatibility for TOML parsing in the umbrella build tests.
- Sdist-derived Core wheels now report the real pinned setuptools generator
  rather than accidentally inheriting the project version.
- Capability-owner diagnostics name current split-Trust write methods.
- Cockpit package and lockfile names now agree.

### Security

- Ready cannot sign or finalize; Trust cannot execute candidate-owned checks.
- Missing credentials fail closed before finalization side effects.
- A green candidate evaluation cannot produce an `ADMITTED` state without an
  authenticated Trust receipt.
