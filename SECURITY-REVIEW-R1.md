# Adversarial review of the R1 integrity subsystem

Date: 2026-08-12. Reviewer: a fresh session with no prior context, instructed to
treat comments, commit messages and tests as untrustworthy.

Threat model: **the attacker is the operator.** Full write access to the log
directory, the source, the index and any key on the machine. Goal: remove
evidence after the fact and still get `verify` → exit 0.

Verdict: **the integrity layer does not hold under this threat model.** Five
distinct routes to exit 0 on a tampered log were confirmed by execution, four of
them requiring no cryptography at all. All findings below were independently
reproduced before being written down.

---

## Confirmed: exit 0 on a tampered log

### C1 — Tail truncation. Three `rm`s, no crypto. CRITICAL

Delete trailing events, the checkpoint covering them, and its anchor files:

    head -20 events-0000.jsonl > t && mv t events-0000.jsonl
    head -2  checkpoints.jsonl > c && mv c checkpoints.jsonl
    rm anchors/00000029.{json,tsr}

Result: `CLEAN, exit 0`, with the flagged exfiltration event gone. Surviving
anchors are genuine, openssl-accepted tokens.

Root cause (`verify.ts`): `lastAnchoredSeq` is computed from the checkpoints
**still on disk**, then only events past it are flagged. Nothing establishes what
the set of checkpoints ought to be. `CheckpointBody` has no index, no
`prev_checkpoint_hash`, and nothing signed says "I am the last". Delete the newest
checkpoint and the log's own idea of its end moves backwards with it.

Reproduced here: 0 tampered findings after truncation.

### C2 — Delete, re-seal, re-anchor. CRITICAL

Delete an event, recompute the chain from genesis, then `rm checkpoints.jsonl
anchors/ signing.key signing.pub.pem` and run the tool's own `checkpoint` and
`anchor` commands with a fresh keypair. Result: `clean, exit 0`.

Nothing pins the signing key (`key_id` is self-asserted and re-derived from
whatever `signing.pub.pem` is on disk), nothing pins the checkpoint count, and
**nothing reads the token's `genTime`**. A checkpoint over last month's events
anchored ten seconds ago is indistinguishable from the real thing. The
`openssl ts -verify` command we print for auditors prints only
`Verification: OK` — it does not show the time, so manual re-verification does
not reveal the re-anchor either.

This is the exact claim in the README, defeated.

### C3 — The poison pill. `count: 0` disables integrity permanently. CRITICAL

`checkCheckpointAgainstEvents` accepts `count: 0`: `inRange.length (0) === count
(0)` and `merkleRoot([]) === emptyRoot()`. So a signed, genuinely anchored
checkpoint claiming `{seq_from: 1000000, seq_to: 9000000, count: 0}` verifies
clean. Plant it once, before doing anything incriminating:

* `lastAnchoredSeq` becomes 9,000,000, so `events_past_last_anchor` can never
  fire again;
* `Recorder`'s cadence never fires again (`from = 9000001`);
* every subsequent event is committed to by nothing, and 30 of them can later be
  deleted, with `verify` printing CLEAN throughout.

### C4 — Total erasure. Zero events, exit 0. CRITICAL

Same `count: 0` hole at the end. Delete everything, write one checkpoint
`{seq_from: 0, seq_to: -1, count: 0}`, sign with a fresh key, anchor for real:
`clean, exit 0, events: 0`. `no_checkpoints` does not fire (there is one), the
step-4 loop passes vacuously, and `events_past_last_anchor` is guarded by
`events.length > 0`.

### C5 — Coverage gaps are silent anywhere but the tail. HIGH

Delete the *middle* or *first* checkpoint plus its anchor, keep every event:
`clean, exit 0`, while a ten-event window is committed to by nothing. The report
still says "every checkpoint anchored". Reproduced here: 0 tampered findings.

### C6 — `openssl` is resolved through the operator's PATH. HIGH

`execFileSync('openssl', ...)` by name. A two-line shim earlier on PATH that
exits 0 turns every corrupted `.tsr` into `anchorsVerified`. Step 3 is the only
thing standing between C2 and a forged token, and it is dispatched by name.
Relatedly, the TSA is never pinned: `tsa_url` in the anchor record is compared to
nothing, so an operator-supplied CA bundle yields clean self-signed timestamps.

### C7 — Duplicate checkpoint lines accepted. MEDIUM

`checkpoints.jsonl` rewritten as `[0,0,1,1,0]` → clean, `checkpoints: 5,
anchorsVerified: 5`. The checkpoint log has no identity or ordering constraints.

---

## Confirmed: canonical JSON collision

`sortKeys` does `out[k] = sortKeys(src[k])`. For `k === "__proto__"` that hits
`Object.prototype`'s setter, creates no own property, and **the key vanishes from
the canonical string**. `JSON.parse` makes `__proto__` a real own property, so it
survives in the file and through `validateEvent` (which rejects no unknown keys).

    canonicalJson({"a":1})                        === {"a":1}
    canonicalJson({"a":1,"__proto__":{"evil":1}}) === {"a":1}     // collision

Reproduced here: `true`. End to end, arbitrary content can be injected into any
event of a fully anchored log — uncommitted by the chain hash, the Merkle root,
the signature and the timestamp — with `verify` reporting clean. Any consumer
that copies events with `Object.assign`/spread resolves those keys as live field
values, so the hashed record and the displayed record diverge by construction.

Ruled out as collisions: `1`/`1.0`/`1e0`, `-0`, duplicate JSON keys,
`NaN`/`Infinity`, 2^53+1. Key sort order matches RFC 8785. The NUL separator in
`hashParts` is sound because `JSON.stringify` escapes U+0000.

---

## Confirmed: Merkle leaves trust attacker-controlled input

`checkCheckpointAgainstEvents` builds leaves from `e.hash` — the stored field —
not from `computeEventHash(e)`. Edit an event's `outcome` and leave its `hash`
alone: the anchored Merkle root still matches perfectly, and only the step-1
chain walk objects. The externally anchored layer therefore commits to *claimed*
digests and provides no independent confirmation of content. Composes with the
`__proto__` hole above.

`verifyChain` advancing `prev` from the stored hash is **not** independently
exploitable — any content edit still trips `computeEventHash(e) !== e.hash`.

---

## Confirmed: DER length parser accepts negative lengths

`length = (length << 8) | byte` is 32-bit signed, so a 4-byte length with the
high bit set yields a negative length that the `end > buf.length` guard misses.
Reproduced here: `readTlv("3084ffffffff")` → `length: -1`.

Consequence: 16 bytes of garbage read as `PKIStatus 0 (granted)` with a token
present, so `anchorCheckpoint` writes it as a valid `.tsr` and `AnchorRecord`.
Two live effects, neither reaching exit 0:

1. **Offline-queue poisoning.** `pendingAnchors` is derived from file existence,
   so one malformed reply permanently stops us ever re-asking the real TSA for
   that checkpoint — silently.
2. **False accusation.** The junk token later makes `verify` report
   `TAMPERED / tsa_verification_failed`. An unparseable file is corruption, not
   proof of rewrite; anyone who can return one bad HTTP response can frame the
   operator.

---

## Other real defects

* **`verify` writes to the artefact it verifies.** It calls `EventStore.open`,
  which `mkdirSync`s the target (verifying a non-existent path *creates* it) and
  `truncateSync`s a torn tail. A second run cannot see what the first destroyed.
* **Corrupt input crashes with exit 1 instead of 2.** Bare `JSON.parse` in
  `readCheckpoints` / `readAnchor` / `store.read`, and no `.catch` in the CLI.
  `echo garbage > checkpoints.jsonl` → stack trace, exit 1 — reported to any
  calling script as TAMPERED, violating our own documented contract.
* **`validateEvent` accepts unknown keys** and never checks `target`, `outcome`
  or `payload_ref`. This is what makes hidden-field injection work.
* **`signing.key` lives in the log directory** beside the data it authenticates,
  making "attacker holds the key" the default configuration.
* **Segment index collisions.** `\d{4,}` means `events-0000` and `events-00000`
  both index 0, ordered by `readdirSync`.

---

## Claims that were stronger than the code

Each of these was in the repo before this review and is now corrected:

* README: "cannot be forged by recomputing hashes, because checkpoints are
  signed *and* anchored" — false. C2 does exactly that; C1 needs no hashing.
* README: the CLEAN/TAMPERED end-to-end demonstration is true only for the lazy
  attacker in `attacker.test.ts`, who leaves the stale checkpoints in place.
* README: "0 clean — every check ran and passed" — vacuous, since nothing checks
  that the checkpoints cover the log. C4 reaches exit 0 having checked nothing.
* `verify.ts`: "A missing anchor … yields 2, never 0" — accurate, and the wrong
  invariant: a *deleted* anchor plus its checkpoint plus its events yields 0.
* The clean banner's "every checkpoint anchored" is literally true and materially
  misleading over a log with a hole in it (C5).
* `checkpoint.ts`: "an attacker cannot produce the old root from the new events"
  — correct and irrelevant; they can delete the old root.
* `schema.ts`: "structurally equal values produce byte-identical output" — the
  converse fails (`__proto__`).

**Note on the test suite:** no test in the tree ever produces a `clean` verdict —
every one passes `skipOpenssl` or a bad CA, so exit 0 is only ever asserted as
*unreachable*. The one clean run was a manual command against freetsa.org. That
is why C1–C5 were invisible: nothing automated ever exercised the success path.

---

## The structural fix

Every critical finding is one bug wearing five hats: **`verify` validates only
what is present, and nothing establishes what should be present.**

Required, in rough priority order:

1. **Make the checkpoint log a chain.** Each `CheckpointBody` carries a monotonic
   index and its predecessor's hash. Enforce `seq_from === prev.seq_to + 1`, the
   first starting at 0, `count >= 1`, `seq_to >= seq_from`. Compare the highest
   anchored `seq_to` against the actual head of the event log. Kills C1, C3, C4,
   C5, C7.
2. **Recompute Merkle leaves** from event content, never from `e.hash`.
3. **Read and check `genTime`** from the token; refuse an anchor materially newer
   than the events it covers. Print the attested time in the auditor command.
   Kills the C2 re-anchor.
4. **Harden `canonicalJson`**: build with `Object.create(null)`, and have
   `validateEvent` reject unknown keys.
5. **Fix the DER length parser**: unsigned arithmetic, reject negative or
   oversized lengths.
6. **Resolve `openssl` to an absolute path; pin the expected TSA.**
7. **Stop the verifier writing to the log directory**; open the store read-only.
8. **Catch parse errors and exit 2**, never 1.
9. **Add a test that reaches a clean verdict**, with a local TSA, so the success
   path is exercised in CI — and then re-run every attack above against it.

Until items 1–3 land, `verify` exit 0 should be read as "no careless tampering
found", not as an integrity guarantee, and nothing in this repo or on the website
may claim otherwise.
