/**
 * R4 — the words. Every user-facing explanation lives here, in one file.
 *
 * Three rules, all enforced by tests in test/explain.test.ts:
 *
 * 1. NO CLAIM STRONGER THAN A TEST PROVES. Green says the witness confirmed
 *    completeness, because a test proves exactly that. Grey says we cannot
 *    rule tampering out — it does NOT say something is wrong, because nothing
 *    has been found wrong. Red names the finding.
 *
 * 2. WRITTEN FOR SOMEONE WHO HAS NEVER HEARD OF A MERKLE ROOT. If a sentence
 *    needs a security background to parse, it fails. Jargon either gets a
 *    plain-English definition in GLOSSARY (shown on hover) or gets cut. A test
 *    scans this file for unexplained terms.
 *
 * 3. THE CAVEATS ARE THE PRODUCT. Anyone can print "verified". The reason to
 *    trust this one is that it is equally clear about what it did not check.
 */

export interface GlossaryEntry {
  /** The word as it appears in copy. */
  term: string;
  /** One sentence, no jargon, no cross-references to other jargon. */
  plain: string;
}

/**
 * Every technical word allowed to appear in user-facing copy.
 *
 * Adding a word here is a promise to explain it in a sentence a non-specialist
 * finishes without a second read. If that cannot be done, the word does not
 * belong in the copy.
 */
export const GLOSSARY: readonly GlossaryEntry[] = [
  {
    term: 'witness',
    plain:
      'An independent service that keeps its own note of what your log contained. '
      + 'Because it is outside your machine, deleting records here does not delete its memory of them.',
  },
  {
    term: 'checkpoint',
    plain:
      'A summary of a batch of recorded actions, signed at the moment it was made. '
      + 'Changing any action in the batch stops the summary from matching.',
  },
  {
    term: 'timestamp authority',
    plain:
      'An outside service that stamps a document with the time, run by someone with no stake in your records. '
      + 'It is what makes "this existed by Tuesday" checkable by a stranger.',
  },
  {
    term: 'anchor',
    plain:
      'A stamp from an outside service proving a batch of records already existed by a certain time. '
      + 'It is what stops someone backdating a rewrite.',
  },
  {
    term: 'fingerprint',
    plain:
      'A short code calculated from a record. Change one character of the record and the code changes completely, '
      + 'so it can be used to tell whether anything was edited.',
  },
  {
    term: 'signing key',
    plain:
      'A private file that marks records as genuinely yours. Anyone can check the mark; only the key can make it.',
  },
  {
    term: 'context',
    plain:
      'Everything the model was given before it answered: the instructions, the conversation so far, '
      + 'and any documents that were pulled in.',
  },
  {
    term: 'tap',
    plain:
      'A relay the agent talks to instead of talking to the model directly, so the exchange can be recorded on the way past.',
  },
  {
    term: 'session',
    plain: 'One run of one agent, from the moment recording started to the moment it stopped.',
  },
];

export function glossaryFor(term: string): GlossaryEntry | undefined {
  return GLOSSARY.find((g) => g.term.toLowerCase() === term.toLowerCase());
}

/** Per-screen explanation. `what` is the one-liner; `detail` expands on it. */
export interface ScreenCopy {
  title: string;
  what: string;
  detail: string;
}

export const SCREENS: Record<'agents' | 'sessions' | 'timeline' | 'evidence' | 'trust', ScreenCopy> = {
  agents: {
    title: 'Agents',
    what: 'Everything on this machine that looks like an AI agent — including things nobody told us about.',
    detail:
      'We read the settings files the common AI tools use, look for stray settings files anywhere else in your home '
      + 'folder, and check what is running right now. The last two are the point: an agent someone installed and '
      + 'forgot is exactly the one missing from a hand-written inventory. Press Record on a row and its actions '
      + 'start being written down. Nothing is recorded until you do.',
  },
  sessions: {
    title: 'Sessions',
    what: 'One row per run. A run starts when recording starts and ends when the agent stops.',
    detail:
      'Restarting an agent begins a new row rather than continuing the old one, because two runs are two different '
      + 'things and merging them would hide a restart. Rows with something flagged are highlighted.',
  },
  timeline: {
    title: 'Timeline',
    what: 'Everything the agent did, in order, grouped by run.',
    detail:
      'Each row is one action: a question put to the model, a tool the agent used, or something we flagged as worth '
      + 'a look. Open a row to see what the agent was given, what it decided, and what came back.',
  },
  evidence: {
    title: 'Evidence',
    what: 'A file you can send to someone else so they can check these records without trusting you — or us.',
    detail:
      'The bundle holds the records, the summaries, the outside timestamps and instructions for checking them with '
      + 'openssl, a standard tool that ships with most computers. It deliberately does not include your signing key '
      + 'or the contents of anything recorded.',
  },
  trust: {
    title: 'Why trust this?',
    what: 'The honest version: what these records prove, what they do not, and how to check for yourself.',
    detail:
      'Every claim on this page has a button next to it that runs the check on your own log, in front of you. '
      + 'It is a live check, not a recording of a demo, and it works on a copy so your records are never touched.',
  },
};

/**
 * The three verdicts, in plain English.
 *
 * The distinction the whole product turns on: RED is an accusation, GREY is an
 * admission. Conflating them either cries wolf or hides a real finding.
 */
export const VERDICTS = {
  green: {
    headline: 'Complete and unaltered',
    lead:
      'Every check passed, including the one that matters most: the witness confirms nothing has been removed '
      + 'from this log.',
    means: [
      'No recorded action has been edited — each one still matches its fingerprint.',
      'No action has been deleted, added, or reordered.',
      'Nothing has been removed from the end, which is the one thing a log cannot detect about itself. '
        + 'The witness is what rules it out.',
      'The times were checked by openssl against the timestamp authority’s own certificate. We did not check '
        + 'our own timestamps and you do not have to take our word for them.',
    ],
    doesNotMean: [
      'That everything the agent did was recorded. We can only show what reached the recorder — if an agent was '
        + 'never connected, nothing here would know.',
      'That the actions were safe or authorised. This says what happened, not whether it should have.',
    ],
  },
  grey: {
    headline: 'Cannot prove completeness',
    lead:
      'Nothing here has been found wrong. There is a check we could not finish, so we cannot rule out that '
      + 'something was removed.',
    means: [
      'This is not a finding of tampering. No edited or missing record has been detected.',
      'It is the honest answer to a question we cannot currently answer: a log on its own cannot show you records '
        + 'that were deleted from the end, because what is left still looks perfectly consistent.',
      'A witness fixes this. It keeps its own note of what this log contained, so deletions here show up as a '
        + 'disagreement.',
    ],
    doesNotMean: [
      'That anything is wrong. Treating this as an alarm would be as misleading as calling it a pass.',
    ],
  },
  red: {
    headline: 'This log has been altered',
    lead: 'A check failed. The details below say which record and what does not add up.',
    means: [
      'Something in this log does not match what was recorded and signed at the time.',
      'This is a factual mismatch, not a judgement about intent: a botched file copy and a deliberate edit look '
        + 'the same from here.',
    ],
    doesNotMean: [
      'That we know who did it or why. The record shows what changed, not who changed it.',
    ],
  },
} as const;

/** Plain-English rendering of a verify finding code. */
export const FINDING_COPY: Record<string, string> = {
  no_witness:
    'No witness is set up, so we cannot tell whether anything was deleted from the end of this log.',
  witness_unreachable:
    'The witness could not be reached, so its copy could not be compared. This is a connection problem, not a finding about your records.',
  witness_missing: 'The witness records for this log could not be found.',
  witness_empty: 'The witness has not been sent anything for this log yet.',
  witness_on_localhost:
    'The witness is running on this same machine, so whoever can change the records can also delete the witness. It has to run somewhere you do not control for its memory to count.',
  witness_inside_log_dir:
    'The witness notes are kept in the same folder as the log. Anyone who can change one can change the other, so they do not add much.',
  no_checkpoints:
    'No summaries have been made yet, so there is nothing to compare this log against.',
  no_public_key: 'The public key needed to check the signatures is missing from this folder.',
  checkpoint_unanchored:
    'A summary has not been timestamped by the outside service yet, so there is no independent proof of when it was made.',
  events_past_last_anchor:
    'Some recent actions are not covered by a timestamped summary yet. This is normal while an agent is still running.',
  checkpoints_not_witnessed:
    'Some summaries have not been sent to the witness yet, so its copy is behind.',
  chain_breaks_truncated:
    'There are too many broken records to list them all. A log this damaged should be treated as lost rather than repaired.',
  prune_not_in_chain:
    'This folder claims some old records were removed on purpose, but the log itself has no record of that happening. A note anyone could drop in is an excuse, not a record.',
  prune_boundary_mismatch:
    'Records were removed on purpose, but the note describing the removal does not line up with the records either side of the gap. It describes a different removal from the one that happened.',
  prune_describes_a_different_range:
    'The note describing a removal does not match the summary it claims to cover — a different set of records, or a different number of them.',
  prune_incomplete:
    'Some records are marked as removed but are still here. The clear-out did not finish; running it again will complete it.',
  signing_key_beside_data:
    'The signing key is stored next to the records it signs. Anyone who can edit the records could re-sign them.',
  openssl_not_found:
    'openssl could not be found, so the outside timestamps could not be checked.',
  no_tsa_ca:
    'The timestamp authority’s certificate was not supplied, so its stamp could not be checked.',
  truncation_detected:
    'The witness remembers records that are no longer in this log. Something was deleted from the end.',
  fork_detected:
    'The witness was sent two different versions of the same batch. The log was rewritten and the new version submitted.',
  witness_mismatch:
    'This log disagrees with what the witness recorded for the same batch. It was changed after the witness saw it.',
  witness_signature_invalid:
    'The reply did not come from the witness we registered with. Either it was substituted or the answer was forged.',
  witness_wrong_log: 'The witness answered about a different log.',
  chain_hash_mismatch: 'A recorded action no longer matches its fingerprint — its contents were edited.',
  chain_prev_hash_mismatch: 'The chain of records is broken here — something was inserted, removed, or reordered.',
  chain_seq_gap: 'A record is missing from the middle of the sequence.',
  checkpoint_root_mismatch: 'A batch of actions no longer matches the summary that was signed for it.',
  checkpoint_count_mismatch: 'A batch contains a different number of actions than its signed summary says.',
  checkpoint_bad_signature: 'A summary’s signature does not check out.',
  anchor_too_late:
    'A batch was timestamped long after the actions it covers. That proves when it was re-stamped, not when the actions happened.',
  event_after_anchor:
    'Actions are dated later than the outside timestamp that covers them. Nothing can be stamped before it happens, so the clock that recorded these actions was wrong.',
  tsa_verification_failed: 'openssl rejected an outside timestamp.',
  anchor_digest_mismatch: 'A timestamp belongs to a different batch than the one it is filed under.',
  unreadable: 'A file could not be read, so the check could not be completed.',
  partial_tail_discarded:
    'The last line of the log was cut off part-way through, which normally means the recorder was killed mid-write. That one action may be missing.',
  log_truncated_below_anchor:
    'A signed summary covers more actions than the log now contains. Actions were removed from the end.',
  tsa_url_mismatch:
    'A timestamp came from a different service than the one expected. A stamp from a service the operator chose does not prove much.',
  tsa_check_skipped: 'The outside timestamps were not checked on this run.',
  tsa_ca_missing:
    'The certificate file needed to check the outside timestamps could not be found at the path given.',
  anchor_time_unreadable: 'The time could not be read out of an outside timestamp.',
  openssl_unavailable:
    'openssl would not run, so the outside timestamps could not be checked. This is a setup problem, not a finding about your records.',
};

export function explainFinding(code: string, fallback: string): string {
  return FINDING_COPY[code] ?? fallback;
}
