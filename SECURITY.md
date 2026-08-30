# Security Policy

## Scope

This policy covers the `orisan-recorder` codebase in this repository — the event
recorder, hash-chained log, checkpoint signing, RFC 3161 anchoring, and witness
client — and its published packages/releases. It does not cover other
Orisan-org repositories (each publishes its own `SECURITY.md`).

## Reporting a Vulnerability

Please report suspected security issues privately. **Do not open a public
GitHub issue for a vulnerability.**

- **Contact:** TODO — no security contact has been published for this repo yet.
  Founder to confirm an address (or a private reporting channel) before this
  file ships.
- **Please include:** affected version or commit, a minimal reproduction, the
  expected versus actual behavior, and whether hash-chain integrity, signing,
  or the witness protocol is implicated.

## Response Time

We aim to acknowledge new reports within **5 business days** of receipt.
*(Proposed default — confirm or adjust before merging.)*

## Disclosure Window

We ask for **90 days** from acknowledgment before public disclosure, to allow
time to validate, fix, and release. We're willing to negotiate a shorter or
longer window with the reporter depending on severity and complexity.
*(Proposed default — confirm or adjust before merging.)*

## Supported Versions

Security fixes are handled on the latest `main` and the current release line.
Older releases are not backported unless a release states otherwise.
