# CLAUDE.md — orisan-recorder

Read before every task. These are non-negotiables, not preferences.
If a request conflicts with this file, stop and say so instead of complying.

## What this is

Records what AI agents do, in a form someone else can check. A hash-chained event
log, signed checkpoints, RFC 3161 timestamps, an external witness. The audience is
an auditor who does not trust us, so the code's job is to be checkable, not
reassuring.

## Invariants

**1. Never described as tamper-proof.** The chain detects careless edits — a flipped
byte, a dropped or reordered record — and names the `seq` where it broke. It does
**not** detect a competent rewrite: every input to the event hash is public, so
anyone who can write the store can recompute from genesis and produce a log that
verifies clean. Signed, anchored checkpoints narrow that; they do not close it.

This is machine-gated, not honour-system. `FALSE_CONFIDENCE_STRINGS` in
[banner.ts](src/banner.ts) bans "tamper-proof", "integrity verified", "chain
verified" and six more; [explain.test.ts](test/explain.test.ts) and
[ui.test.ts](test/ui.test.ts) assert them against the **built UI bundle**, so a
reassurance hard-coded in a React component is caught too. Do not weaken that list.
Say what verify proves and what it does not, every time.

**2. Determinism where it is hashed.** `canonicalJson`, `hashParts`,
`computeEventHash`, the Merkle tree and chain verification are pure — same input,
byte-identical output on every platform, or the log is not portable.

The recorder as a whole is *not* deterministic and must not be described that way:
it stamps `randomUUID()` and wall-clock `ts`. Those enter through **injectable
seams** — `opts.now`, `sessionId`, `event_id`, `ts`. Keep them injectable. New
nondeterminism that a test cannot pin is a defect.

**3. No LLM anywhere in recording or verification.** There is no model call in this
repo and there must never be one. [tap.ts](src/tap.ts) *observes* provider traffic
(anthropic/openai) and parses usage; it never originates a call. A judgement made
by a model is not evidence an auditor can re-derive.

**4. No telemetry.** Nothing phones home. Runtime deps are `better-sqlite3` and
`sodium-native`; the UI is React and nothing else. Do not add an analytics,
crash-reporting or update-check dependency.

Network egress is exactly two deliberate, user-facing paths — state them rather
than claiming "no network": the RFC 3161 anchor in [tsa.ts](src/tsa.ts)
(`DEFAULT_TSA_URL`, fetch is injectable for tests) and a TSA CA fetch in
[showcase.ts](src/showcase.ts). Verification of an existing log runs offline.

**5. Payloads are off unless a key is configured.** `payload_ref` is `null` and no
blob is written when no payload key is present ([tap.ts](src/tap.ts),
[server.ts](src/server.ts)). Prompts and arguments are **never inlined into an
event** — the log is append-only, so anything sealed into a record is unremovable.
They live in separate sealed blobs so an erasure request is satisfied by destroying
a blob or its key while the chain still verifies.

## Security-critical paths

Changes here need adversarial review, not just a passing suite:

- [schema.ts](src/schema.ts) — canonical JSON, event hash, chain walk. The
  `Object.create(null)` in `sortKeys` is load-bearing: with a plain `{}`, the key
  `__proto__` hits `Object.prototype`'s setter and **vanishes** from the canonical
  string, so arbitrary content could ride inside an anchored event uncommitted by
  the hash, root, signature and timestamp. Never "simplify" it.
  NUL-joining in `hashParts` is load-bearing for the same class of reason:
  plain concatenation makes `("ab","c")` and `("a","bc")` collide.
- [merkle.ts](src/merkle.ts), [checkpoint.ts](src/checkpoint.ts),
  [checkpoint-sign.ts](src/checkpoint-sign.ts) — roots and signatures.
- [tsa.ts](src/tsa.ts), [der.ts](src/der.ts) — DER parsing of attacker-supplied
  bytes. A negative-length bug was already found here once.
- [verify.ts](src/verify.ts), [banner.ts](src/banner.ts) — the verdict, and the
  words used to report it. Exit code and banner must agree.
- [payloads.ts](src/payloads.ts) — sealed blobs. Use the audited primitive
  (`crypto_box_seal`) unmodified; do not hand-roll an envelope again.
- [witness.ts](src/witness.ts), [prune.ts](src/prune.ts) — external anchoring, and
  the only sanctioned way a gap in the log is explained rather than suspicious.

[SECURITY-REVIEW-R1.md](SECURITY-REVIEW-R1.md) lists the confirmed attacks (C1–C7).
Every one runs in CI on every push. Read it before touching the above.

## Commands

```
npm test           # vitest; `pretest` builds first, so this works on a fresh clone
npm run typecheck  # tsc --noEmit, both src and test projects
npm run build      # tsc + UI bundle
npx vitest run test/attacks.test.ts test/attacker.test.ts test/hardening.test.ts
```

Run `npm test` and `npm run typecheck` before opening a PR. `tsconfig` is strict
with `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes` — respect both.

## Rules for tests

A green suite is not evidence a test ran. `describe.skip` is green, and that is how
the witness suites once passed while executing nothing.

- **Every check must assert it examined something** — a minimum subject count, or a
  synthetic positive case it must catch. A control that cannot fail is not a
  control. This applies when writing a check, not only when reviewing one.
- `scripts/assert-attacks-ran.mjs` and `scripts/assert-witness-ran.mjs` enforce that
  for the attack and witness suites. Do not delete or loosen them.
- Never edit a gate to make your work pass. If a gate is wrong, say so and stop.
- Test against the built artefact when the claim is about the shipped thing
  (the UI bundle, `dist/cli.js`), not only the module.
