# orisan-recorder

A recorder for AI agent actions.

Two properties are the point of this project, in order:

1. **Discovery.** We find every agent and MCP server on the machine, so the record
   can claim to be *complete*. (Slice R2.)
2. **Witnessed integrity.** Checkpoints are signed and anchored to an external RFC
   3161 timestamp authority. **This does not yet hold under a hostile operator** —
   see `SECURITY-REVIEW-R1.md`. Do not repeat this as a guarantee until the fixes
   listed there have landed.

## Why the hash chain alone is not enough

A competitor teardown established this empirically: a plain hash chain over public
inputs is forgeable by anyone who can write to the store. Delete the inconvenient
records, recompute every hash from genesis with the tool's own hash function, and
verification passes. Two shipping products certify such a log as untampered — one of
them under a valid signature.

So: **nothing in this repo should ever describe the chain by itself as tamper-proof.**
The chain detects careless edits. Only a signed checkpoint anchored outside our
control detects a competent rewrite. Until R1.3 lands, this recorder has the weaker
property, and says so.

A second rule taken from the same teardown: **we never verify our own time proof.**
`verify` shells out to `openssl ts -verify` for the RFC 3161 check and prints the
command it ran, so a reviewer trusts no code of ours for that step.

## Status

| Slice | What | State |
|---|---|---|
| R1.1 | Versioned event schema + hash chain | done |
| R1.2 | Append-only store, SQLite index, encrypted payloads | done |
| R1.5 | Fake session generator (`demo`) | done |
| R1.3 | Signed checkpoints + RFC 3161 anchoring | done (Tier C) |
| R1.4 | `verify` command | done (Tier C) |
| R2 | Discovery, attach/detach, local UI | not started |

All R1 acceptance tests pass, including `test/attacker.test.ts`: the recompute
attack (delete events, re-seal the chain with our own hash function — `verify`
exits 1 naming the checkpoint) and the TSA-unreachable case (recording continues,
the checkpoint queues, `verify` exits 2 and never reports clean). Verified end to
end against the live freetsa.org.

**Those tests describe a careless attacker.** An adversarial review
(`SECURITY-REVIEW-R1.md`) found five confirmed routes to `exit 0` on a tampered
log, four needing no cryptography — the simplest is deleting trailing events
together with the checkpoint and anchor that covered them. The root cause is that
`verify` validates only what is present and nothing establishes what should be
present. Until the fixes in that document land, read `exit 0` as "no careless
tampering found", not as an integrity guarantee.

## Layout

    src/schema.ts     R1.1  event shape, canonical JSON, chain hashing
    src/store.ts      R1.2  append-only segments, fsync, crash recovery
    src/index-db.ts   R1.2  SQLite index (a cache; the JSONL is the truth)
    src/payloads.ts   R1.2  sodium crypto_box_seal payload blobs   [Tier C]
    src/merkle.ts     R1.3  RFC 6962 Merkle tree
    src/checkpoint.ts R1.3  Ed25519-signed checkpoints             [Tier C]
    src/der.ts        R1.3  minimal DER for RFC 3161
    src/tsa.ts        R1.3  timestamp anchoring + offline queue     [Tier C]
    src/recorder.ts   R1.3  store + checkpoint cadence
    src/verify.ts     R1.4  the verify command                      [Tier C]
    src/demo.ts       R1.5  fake session generator
    src/cli.ts              CLI surface

## verify exit codes

    0  clean          every check ran and passed
    1  tampered       a break, a bad signature, or a violated anchored root
    2  cannot-verify  a check could not be completed — NEVER a pass

Exit 2 is the code competitors get wrong. "I could not check" is not "it is fine".
A missing anchor, a missing public key, or an openssl that will not run all yield 2.

Caveat from the review: a *deleted* anchor, together with its checkpoint and the
events it covered, currently yields 0. That is the top open defect.

## Development

    npm install
    npm run typecheck
    npm test

Node 20+. No GNU-only flags anywhere: the recorder must behave identically on macOS
and Linux, and a competitor shipped a macOS-dead feature by calling `ps --no-headers`
inside a bare `except: pass`. Cross-platform CI lands with the rest of R1.
