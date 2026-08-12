/**
 * R2.4 — the integrity banner. TIER C: read every line, and read the strings.
 *
 * This is the single most dangerous surface in the product. Everything else
 * either works or visibly does not; a banner can be confidently wrong and look
 * fine. The competitor teardown that started this project found two shipping
 * tools printing "no tampering detected" over logs whose incriminating records
 * had been deleted. That artefact — a reassuring green badge on a falsified
 * record — is the thing we exist not to produce.
 *
 * Three states, mapped one-to-one from verify's exit code. No fourth state, no
 * partial credit, no "mostly verified".
 *
 *   exit 0  -> GREEN   integrity verified
 *   exit 1  -> RED     tampered
 *   exit 2  -> GREY    cannot prove completeness
 *
 * Rules that hold regardless of what anyone adds later:
 *
 *  1. GREEN is reachable only from exit 0. Not from "no findings", not from
 *     "nothing looked wrong", not from a verify that could not run.
 *  2. The word "verified" appears in exactly one state: green. Grey and red
 *     text must not contain it in any form, including negated ("not verified"),
 *     because a screenshot of half a sentence is what ends up in a deck.
 *  3. Grey is not a warning and not a failure. It is the honest answer to a
 *     question we cannot answer yet, and it says what would change that.
 *
 * The tone difference matters: red accuses, grey admits. Conflating them either
 * cries wolf or hides a real finding, and both destroy the signal.
 */

export type BannerTone = 'green' | 'red' | 'grey';

export interface Banner {
  tone: BannerTone;
  /** Short label. The only string a user reliably reads. */
  headline: string;
  /** One line of plain English under the headline. */
  detail: string;
  /** Where to read more. */
  docsHref: string;
  /** Findings worth naming, most important first. */
  findings: { code: string; message: string }[];
}

export interface BannerInput {
  exitCode: number;
  findings: readonly { severity: string; code: string; message: string }[];
}

export const DOCS_HREF = 'https://github.com/orisan/orisan-recorder#what-verify-proves-and-what-it-does-not';

/**
 * Strings that must never appear outside a green banner.
 *
 * Checked by a test against the BUILT UI BUNDLE, not just this module, because
 * a hard-coded reassurance in a React component would never pass through here.
 */
export const FALSE_CONFIDENCE_STRINGS: readonly string[] = [
  'integrity verified',
  'no tampering detected',
  'tamper-proof',
  'tamper proof',
  'cryptographically verified',
  'fully verified',
  'all events verified',
  'chain verified',
];

export function bannerFor(input: BannerInput): Banner {
  const named = input.findings.map((f) => ({ code: f.code, message: f.message }));

  if (input.exitCode === 1) {
    const worst = input.findings.filter((f) => f.severity === 'tampered');
    return {
      tone: 'red',
      headline: 'TAMPERED',
      detail:
        worst.length > 0
          ? worst[0]!.message
          : 'This log does not match what was signed and externally timestamped.',
      docsHref: DOCS_HREF,
      findings: named,
    };
  }

  if (input.exitCode === 0) {
    return {
      tone: 'green',
      headline: 'Integrity verified',
      detail:
        'Every check ran and passed: the chain is intact, every checkpoint is signed, and every '
        + 'checkpoint is anchored to an external timestamp authority that accepted it.',
      docsHref: DOCS_HREF,
      findings: [],
    };
  }

  // Everything else — including any exit code we do not recognise — is grey.
  // Defaulting an unknown code to green would be the exact failure this file
  // exists to prevent, so the fallback leans the safe way.
  const witnessMissing = input.findings.some(
    (f) => f.code === 'no_witness' || f.code === 'witness_missing' || f.code === 'witness_empty',
  );
  return {
    tone: 'grey',
    headline: 'Cannot prove completeness',
    detail: witnessMissing
      ? 'No witness is configured, so deleting events together with the checkpoints covering them '
        + 'would leave a log that still looks consistent. Nothing here says this log was altered — '
        + 'only that we cannot rule it out.'
      : 'A check could not be completed, so this log is unproven. Nothing here says it was altered.',
    docsHref: DOCS_HREF,
    findings: named,
  };
}

/** Guard usable at runtime and in tests: does this text overclaim for its tone? */
export function overclaims(tone: BannerTone, text: string): string[] {
  if (tone === 'green') return [];
  const lower = text.toLowerCase();
  return FALSE_CONFIDENCE_STRINGS.filter((s) => lower.includes(s));
}
