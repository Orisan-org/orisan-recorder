# orisan-recorder

A recorder for AI agent actions.

Two properties are the point of this project, in order:

1. **Discovery.** Find every agent and MCP server on the machine, so the record can
   claim to be *complete*. `orisan-rec scan` reads the known config locations for
   seven surfaces, hunts stray `mcpServers` files nobody registered, and looks at
   running processes. Every server carries how it was found. No competitor can
   name an agent it was not told about.
2. **Witnessed integrity.** Make the log expensive to rewrite even for the person
   who owns the machine it runs on. (Slices R1.3–R1.5, built; see the exact claim
   below.)

## What `verify` proves, and what it does not

This section is the contract. No sentence here is stronger than a test in
`test/attacks.test.ts`, and every attack listed in `SECURITY-REVIEW-R1.md` runs in
CI permanently.

**With a witness held outside the operator's control, and a pinned TSA, `verify`
detects:**

| Attack | Caught by |
|---|---|
| Editing an event | chain walk, naming the seq |
| Editing an event but keeping its stored hash | Merkle root, recomputed from content |
| Deleting or reordering events | chain walk + anchored Merkle root |
| Re-sealing the whole chain from genesis | anchored checkpoint root |
| Deleting a checkpoint from the middle | checkpoint chain: index gap, seq discontinuity |
| A `count: 0` checkpoint over a huge range | `count >= 1` is enforced |
| Erasing everything and starting over | witness, and `count >= 1` |
| Deleting the tail — events, checkpoint and anchors together | **witness only** — `truncation_detected` |
| Re-sealing and re-submitting to the witness | witness records a fork — `fork_detected` |
| Substituting a different witness | the witness key is pinned at registration |
| Re-anchoring old events today | attested `genTime`, 1-hour window |
| Swapping in another authority's timestamp | `--tsa` pinning |
| A `PATH` shim standing in for openssl | openssl resolved to an absolute path |

**It does not prove:**

- **That every action reached the recorder.** Nothing here observes an agent that
  was never instrumented. That is capture completeness, a property of where the
  recorder sits, and it is what R2's discovery is for. A log can be perfectly
  verifiable and still be missing everything that matters.
- **Completeness without a witness.** A self-held log cannot detect suffix
  deletion: truncating the trailing events together with the checkpoints covering
  them leaves a valid prefix, indistinguishable from a log that ended earlier.
  With no witness `verify` returns exit 2, never 0, and says why. Register one
  with `orisan-rec witness register` — see `~/Orisan/orisan-witness`.
- **Anything about a witness the operator can rewrite.** A witness inside the log
  directory is reported and not counted.
- **That the timestamp is genuine.** We never verify our own time proof. `verify`
  shells out to `openssl ts -verify`, prints the exact command, and prints the
  attested time so a human re-running it knows what to expect — "Verification: OK"
  on its own hides a re-anchoring.
- **Non-repudiation.** The signing key identifies the recorder, not a person.

## Exit codes

    0  clean          every check ran and passed
    1  tampered       a break, a bad signature, a violated anchored root,
                      a broken checkpoint chain, or a witness disagreement
    2  cannot-verify  a check could not be completed — NEVER a pass

Exit 2 is the code competitors get wrong. "I could not check" is not "it is fine".
No witness, no anchor, no public key, no TSA CA, an unresolvable openssl, or a
corrupt file all yield 2. Reaching 0 requires every check to have actually run.

## Custody: the part that is operational, not cryptographic

Three things must live somewhere the recorder's operator cannot silently rewrite,
or the guarantees above degrade to "no careless tampering found":

- **the witness** (`orisan-rec witness register --url …`) — the only defence
  against tail truncation. Its key is pinned at registration and never
  re-learned; a response signed by another key fails hard as an attack.
  A local `--witness <file>` is the weaker, self-hosted form.
- **the signing key** (`--key`, default `~/.orisan/signing.key`) — a key beside the
  data lets whoever rewrites the log re-sign it; `verify` reports it if it finds one
- **the TSA** (`--tsa`) — an operator-chosen authority proves nothing

## Quick start

    npm install && npm run build:ui

    npx tsx src/cli.ts scan                       # what is on this machine
    npx tsx src/cli.ts demo /tmp/session --with-ui  # seeded session + UI, no agents needed

    # record a real agent
    npx tsx src/cli.ts attach "<mcp config>" --log /tmp/session --key ~/.orisan/signing.key
    npx tsx src/cli.ts detach "<mcp config>"      # restores byte-identical

    npx tsx src/cli.ts checkpoint /tmp/session
    npx tsx src/cli.ts anchor /tmp/session
    npx tsx src/cli.ts verify /tmp/session --tsa-ca ca.pem --witness ~/witness.jsonl

## The local UI

`orisan-rec ui <dir>` serves http://127.0.0.1:4173 — Agents, Sessions, Timeline,
Evidence. It binds loopback only and has **no authentication**: the binding is the
access control, and requests without a loopback `Host` header are refused so a
rebinding page cannot drive the API from a browser tab.

The integrity banner has exactly three states, mapped from `verify`'s exit code:
green only at 0, red at 1, grey at 2 — and an unrecognised code falls back to grey.
Today, with no witness configured, it shows **grey "Cannot prove completeness"**,
never green. A test greps the built UI bundle for false-confidence strings.

## The tap: model calls

`orisan-rec tap <dir> --upstream https://api.anthropic.com --payload-key <path>`
runs an HTTP proxy the agent points its base URL at. Every model call is
recorded: the full context in and the decision out.

Two rules, both tested:

- **Fail open.** Every capture path is wrapped and runs after the response is
  closed out. If the recorder cannot open, if sealing fails, if the tap has a
  bug — the request still reaches the model and the response still reaches the
  agent. There are tests that break sealing, break the recorder, and kill the
  upstream, and assert the call still succeeds.
- **Every captured context is encrypted.** A model call carries the whole
  prompt. It goes through the same sodium `crypto_box_seal` path as any other
  payload or it is not captured at all — `--payload-key` is required, and
  `--no-context` is the only way to run without it. Tests assert the prompt
  appears in neither the event log nor the blob bytes, and that the key holder
  can read both context and decision.

The event itself holds only non-secret facts: provider, model, message and tool
counts, stop reason, tool names, token usage, duration, a digest over the
canonical request, and the `payload_ref`.

**Measured overhead** on an 80KB context against a local upstream, 300 calls:
median **+1.29ms** buffered, **+1.25ms** streaming (p95 +1.7ms / +2.0ms). Against
a real provider that is well inside the noise.

## Attach / detach

`attach` rewrites an MCP config so each stdio server runs behind a passthrough
shim. The backup is written before the original is touched; `detach` restores it
**byte-identically** and throws if it cannot.

The shim forwards stdio first and records afterwards, always. If recording fails —
disk full, unwritable log, a bug in us — the agent still works. That is the
opposite of the recorder core, where a failed append is fatal, and both directions
are deliberate: here the user's workflow wins, there the evidence does.

## Status

| Slice | What | State |
|---|---|---|
| R1.1 | Versioned event schema + hash chain | done |
| R1.2 | Append-only store, SQLite index, sealed payloads | done |
| R1.3 | Merkle roots, signed checkpoints, RFC 3161 anchoring, witness | done |
| R1.4 | `verify` | done |
| R1.5 | `demo` | done |
| R2.1 | Discovery scan | done |
| R2.2 | attach / detach + passthrough shim | done |
| R2.3 | Local UI, evidence export | done |
| R2.4 | Integrity banner | done |
| W1 | External witness: register, submit, verify against it | done |
| R3 | Relay tap: model calls, encrypted context | done |
| — | Kill switch | not started |

`SECURITY-REVIEW-R1.md` records an adversarial review that found five routes to
exit 0 on a tampered log. All five are closed and all five are permanent tests.
The review's own findings section is left intact rather than edited down, because
the list of what was wrong is more useful than a claim that nothing is.

## Layout

    src/schema.ts     event shape, canonical JSON, chain hashing
    src/store.ts      append-only segments, fsync, crash recovery, read-only mode
    src/index-db.ts   SQLite index (a cache; the JSONL is the truth)
    src/payloads.ts   sodium crypto_box_seal payload blobs
    src/merkle.ts     RFC 6962 Merkle tree
    src/checkpoint.ts Ed25519-signed, chained checkpoints
    src/der.ts        minimal DER for RFC 3161
    src/tsa.ts        timestamp anchoring, offline queue, attested time
    src/witness.ts    external witness log
    src/recorder.ts   store + checkpoint cadence
    src/verify.ts     the verify command
    src/discover.ts   R2 discovery scan
    src/attach.ts     R2 config rewrite / restore
    src/shim.ts       R2 stdio passthrough recorder
    src/server.ts     R2 local UI server (loopback only)
    src/banner.ts     R2 integrity banner  [Tier C]
    src/witness-service.ts  W1 witness client, pinned key  [Tier C]
    src/tap.ts        R3 model-call tap: fail-open, encrypted context
    src/bundle.ts     R2 evidence bundle
    src/zip.ts        minimal zip writer
    src/demo.ts       fake session generator
    src/cli.ts        CLI surface
    ui/               React + Vite single page

## Development

    npm run typecheck
    npm test

Node 20+. No GNU-only flags: a competitor shipped a macOS-dead feature by calling
`ps --no-headers` inside a bare `except: pass`, and the tests are cross-platform
for that reason. The TSA fixture in `test/fixtures/` runs a real local timestamp
authority so CI exercises the success path offline — the absence of that is why
five criticals shipped unnoticed.
