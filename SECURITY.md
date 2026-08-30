# Security policy

Admissible treats candidate execution and trusted finalization as separate
authorities. Security reports that could enable a bypass should not be filed as
public issues.

## Supported versions

| Version | Status |
|---|---|
| 0.8.x | Supported after public release |
| 0.7.x monolith | Compatibility window only; migration fixes at maintainer discretion |
| Earlier versions | Unsupported |

No version is considered publicly released until its annotated Git tag and GitHub
Release are published from the accepted source commit.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** flow for this repository:

https://github.com/prive-hn/admissible/security/advisories/new

Include the affected version or commit, the authority boundary involved, a
minimal reproduction, expected versus observed behavior, and whether any key,
receipt, policy, journal, or candidate-controlled process is involved. Do not
include production secrets or personal data. If private vulnerability reporting
is temporarily unavailable, contact the repository owner through the
`prive-hn` organization profile and ask for a private channel before sending
technical details.

Maintainers will acknowledge a complete report, reproduce it against an exact
commit, assess impact, and coordinate disclosure. No fixed response time is
promised in this initial release.

## Security boundaries

High-priority reports include:

- candidate code reaching a Trust key or finalization path;
- Trust executing candidate-owned commands;
- unsigned or unauthenticated data producing `ADMITTED`;
- receipt, policy, journal, or standing tampering that verifies;
- package contents crossing the Core/Ready/Trust boundary;
- a documented fail-closed path silently falling back or passing;
- build artifacts that cannot be bound to their reviewed source.

The papers state assumptions and non-claims. Findings that violate an explicit
assumption may still be useful, but should not be described as breaking a
theorem unless the implementation claims to enforce that assumption.
