# orisan-recorder

A recorder for AI agent actions.

Two properties are the point of this project, in order:

1. **Discovery.** We find every agent and MCP server on the machine, so the record
   can claim to be *complete*. (Slice R2.)
2. **Witnessed integrity.** Our log cannot be forged by recomputing hashes, because
   checkpoints are signed *and* anchored to an external RFC 3161 timestamp authority.
   (Slice R1.3/R1.4.)

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
| R1.3 | Signed checkpoints + RFC 3161 anchoring | **not started** (Tier C) |
| R1.4 | `verify` command | **not started** (Tier C) |
| R2 | Discovery, attach/detach, local UI | not started |

Because R1.3/R1.4 are not built, the acceptance tests that depend on them — the
recompute attack and the TSA-unreachable case — are present as skipped placeholders,
not as passes. See `test/attacker.test.ts`.

## Layout

    src/schema.ts    R1.1  event shape, canonical JSON, chain hashing
    src/store.ts     R1.2  append-only segments, fsync, crash recovery
    src/index-db.ts  R1.2  SQLite index (a cache; the JSONL is the truth)
    src/payloads.ts  R1.2  encrypted payload blobs  [Tier C — needs review]
    src/demo.ts      R1.5  fake session generator
    src/cli.ts             minimal CLI surface

## Development

    npm install
    npm run typecheck
    npm test

Node 20+. No GNU-only flags anywhere: the recorder must behave identically on macOS
and Linux, and a competitor shipped a macOS-dead feature by calling `ps --no-headers`
inside a bare `except: pass`. Cross-platform CI lands with the rest of R1.
