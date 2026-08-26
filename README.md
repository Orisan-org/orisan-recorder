# orisan-recorder

[![CI](https://github.com/rakeshb114/orisan-recorder/actions/workflows/ci.yml/badge.svg)](https://github.com/rakeshb114/orisan-recorder/actions/workflows/ci.yml)

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
`test/attacks.test.ts`, and every confirmed attack in `SECURITY-REVIEW-R1.md`
(C1 to C7) runs in CI on every push and every pull request, on Linux and macOS,
on Node 20 and 22 — see [.github/workflows/ci.yml](.github/workflows/ci.yml).

A green suite would not establish that on its own: a skipped test is green, a
renamed one is green, and a deleted one is greenest. So CI also runs
[`scripts/assert-attacks-ran.mjs`](scripts/assert-attacks-ran.mjs), which fails
if any of C1-C7 was skipped, renamed or removed, and fails if the review
documents an attack that is not wired to a test at all. The claim is about
execution, so it is checked on execution.

The witness suites (W1 to W5, in `test/witness-attacks.test.ts`) are a separate
set and are **not** part of that claim. They need the `orisan-witness` service
from a sibling repository, so they skip in CI and in any clone without it. When
they skip they are reported as skipped, never as passed, and the run prints
which checks did not happen and what they cover.

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

## One writer per log directory

A log directory takes exactly one recorder at a time, enforced by `writer.lock`
in that directory. A second writer refuses to start and names the process
holding it; it does not queue and it does not proceed.

This is not tidiness. Sequence numbers and the running chain hash live in the
writing process's memory, so two recorders both believe they own the head and
both write it — 30 events each produced 60 lines with 30 distinct sequence
numbers, every one duplicated with a different `prev_hash`. Nothing on disk
records which ordering really happened, so the log cannot be repaired
afterwards, only discarded.

A lock naming a dead process **on this host** is reclaimed automatically, so a
recorder killed with SIGKILL does not brick the directory. A lock from another
hostname is refused instead, because this machine cannot ask whether that
process is alive and guessing wrong causes the corruption the lock prevents.

Reading is never blocked: `verify`, the UI and every export open read-only, take
no lock, and work fine against a log that is being written.

## Retention

    orisan-rec prune <dir> --keep-last 5
    orisan-rec prune <dir> --before 2026-01-01 --dry-run

A log only grows. But deleting old events IS the truncation attack, so pruning
has to be something a verifier can tell apart from one.

**Events are removed; checkpoints and anchors are kept.** A checkpoint is a few
hundred bytes committing to a Merkle root over its range — the events are the
megabytes. Keeping the signed, externally timestamped checkpoint leaves proof of
exactly what used to be there, fixed in time before anyone could choose what to
delete. A pruned range is not a hole in the evidence; it is a range whose
contents are gone but whose fingerprint is not.

Four rules, all enforced by `verify`:

1. **Whole ranges only.** Never part of a checkpoint — half a range would leave
   a retained root that could never be recomputed and never be shown wrong.
2. **Anchored ranges only.** Without an external timestamp there is no proof of
   what the range held before someone decided to remove it. Not overridable.
3. **It is recorded in the log.** A `prune` event goes into the chain and its
   `args_digest` commits to the manifest entry in `prunes.jsonl`. A manifest on
   its own proves nothing — anyone can write a file. The chain has to vouch for
   it.
4. **The chain stays walkable.** The manifest records the boundary hashes, so
   the event after a gap still links to what preceded it.

Measured on a real 20,000-event log with four anchored checkpoints: 21 MB to
11 MB, 15,000 events removed, every checkpoint and anchor retained, and verify
reports `pruned: 15000` with no tampered finding.

Remove the same bytes without the record and it is tampering, which is the
point:

    TAMPERED [seq 15000] chain_seq_gap
    TAMPERED [checkpoint ..4999] checkpoint_count_mismatch

Pruning is not reversible, and pruned content cannot be recovered from the log.
It is a decision to keep the proof and drop the detail, taken on the record.

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

## See it work

    orisan-rec showcase

Forty-five seconds, no typing: discovery, a recorded session, a signed and
externally timestamped batch, a CLEAN check, then the end of the log is deleted
— the chain-only check calls it intact, and the full check catches it because
the witness still remembers. Recording and screenshots in [media/](media/).

It runs the real commands as subprocesses, against the live witness and a real
timestamp authority. If a step misbehaves it prints SHOWCASE FAILED and exits
non-zero rather than reaching a reassuring ending.

## Install

**Today, from a checkout** — this is the path that works right now:

    git clone <repo> && cd orisan-recorder
    npm install && npm run build
    node dist/cli.js start

**Once published**, the one-liner below will do the same thing. It does not
work yet: `orisan.org` does not serve `install.sh`, and `orisan-recorder` is
not on the npm registry. The script is written and tested — it installs
correctly from a local tarball — but the hosted command is not a claim we can
make until both are true.

    curl -fsSL https://orisan.org/install.sh | sh    # not live yet

Either path needs Node 20+ and nothing else — no key, no account, no config
file. It installs into `~/.orisan/app` (never globally, never `sudo`), creates
your keys outside the log folder, writes a short clearly-labelled example
session so the first screen has something in it, and opens the interface.

Then it tells you what is still missing and what each piece would buy. The
banner stays **grey** until a witness is registered — that is not a warning, it
means completeness has not been established yet and the interface says so
rather than implying more than it can show.

    orisan-rec start          # set up and open the interface
    orisan-rec scan           # what agents are on this machine
    orisan-rec attach <cfg> --log <dir>   # record one; detach restores it byte-identically
    orisan-rec tap <dir> --upstream https://api.anthropic.com --payload-key <p>
    orisan-rec checkpoint <dir> && orisan-rec anchor <dir>
    orisan-rec witness register <dir> --url <witness>
    orisan-rec witness repoint <dir> --url <new>   # move to a new hostname
    orisan-rec verify <dir> --tsa-ca ca.pem

### From a checkout

    npm install && npm run build
    node dist/cli.js start

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
| R4 | Explainability: plain English, Prove it, auditor README, tour | done |
| R5 | Packaging: one-command install | done |
| — | Kill switch | not started |

`SECURITY-REVIEW-R1.md` records an adversarial review that found five routes to
exit 0 on a tampered log. All five are closed and all five are permanent tests.
The review's own findings section is left intact rather than edited down, because
the list of what was wrong is more useful than a claim that nothing is.

## Layout

    src/schema.ts     event shape, canonical JSON, chain hashing
    src/store.ts      append-only segments, fsync, crash recovery, read-only mode
    src/lock.ts       exclusive writer lock on a log directory
    src/prune.ts      retention: drop old events, keep the proof
    src/index-db.ts   SQLite index (a cache; the JSONL is the truth)
    src/payloads.ts   sodium crypto_box_seal payload blobs
    src/merkle.ts     RFC 6962 Merkle tree, batch and streaming
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
