/**
 * R4 — the copy is tested like code.
 *
 * "Write it for someone who does not know what a Merkle root is" is only a
 * rule if something enforces it. These tests are that something.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { FALSE_CONFIDENCE_STRINGS } from '../src/banner.js';
import { FINDING_COPY, GLOSSARY, SCREENS, VERDICTS, explainFinding, glossaryFor } from '../src/explain.js';

/** Every sentence a user can see, from one place. */
function allCopy(): string {
  const parts: string[] = [];
  for (const s of Object.values(SCREENS)) parts.push(s.title, s.what, s.detail);
  for (const v of Object.values(VERDICTS)) parts.push(v.headline, v.lead, ...v.means, ...v.doesNotMean);
  parts.push(...Object.values(FINDING_COPY));
  return parts.join('\n');
}

describe('no unexplained jargon', () => {
  /**
   * Words a non-specialist cannot be expected to know. Each must either be
   * absent from the copy or carry a glossary entry shown on hover.
   */
  const JARGON = [
    'merkle', 'hash chain', 'sha-256', 'sha256', 'ed25519', 'rfc 3161', 'rfc3161',
    'nonce', 'canonical', 'spki', 'pem', 'der', 'asn.1', 'x25519', 'hmac',
    'idempotent', 'append-only', 'genesis', 'preimage', 'entropy', 'cryptographic',
    'seq', 'prev_hash', 'payload_ref', 'merkle root',
  ];

  it('none of the hard words appear in user-facing copy', () => {
    const copy = allCopy().toLowerCase();
    // Whole words only: "der" must not match inside "under", nor "seq" inside
    // "sequence". A substring check here produces noise and gets switched off,
    // which is how a jargon guard quietly stops guarding anything.
    const found = JARGON.filter((w) => {
      const escaped = w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`).test(copy);
    });
    expect(found, `unexplained jargon in copy: ${found.join(', ')}`).toEqual([]);
  });

  it('every glossary term is defined without needing another glossary term', () => {
    for (const entry of GLOSSARY) {
      const others = GLOSSARY.filter((g) => g.term !== entry.term).map((g) => g.term);
      const leaning = others.filter((o) => entry.plain.toLowerCase().includes(o.toLowerCase()));
      expect(leaning, `"${entry.term}" is defined using ${leaning.join(', ')}`).toEqual([]);
    }
  });

  it('glossary definitions are one or two sentences, not a paragraph', () => {
    for (const entry of GLOSSARY) {
      const sentences = entry.plain.split('. ').filter((x) => x.trim().length > 0);
      expect(sentences.length, `"${entry.term}" runs to ${sentences.length} sentences`).toBeLessThanOrEqual(2);
    }
  });

  it('lookup is case-insensitive and misses cleanly', () => {
    expect(glossaryFor('WITNESS')?.term).toBe('witness');
    expect(glossaryFor('flux capacitor')).toBeUndefined();
  });
});

describe('the verdicts say what they do NOT mean', () => {
  it('every verdict carries limits, not just claims', () => {
    for (const [tone, v] of Object.entries(VERDICTS)) {
      expect(v.means.length, `${tone} has no means`).toBeGreaterThan(0);
      expect(v.doesNotMean.length, `${tone} has no doesNotMean`).toBeGreaterThan(0);
    }
  });

  it('green credits the witness for completeness, and does not overclaim coverage', () => {
    const g = VERDICTS.green;
    expect(g.lead).toMatch(/witness/i);
    expect(g.means.join(' ')).toMatch(/removed from the end/i);
    // The limit that matters: we cannot prove we saw everything.
    expect(g.doesNotMean.join(' ')).toMatch(/only show what reached the recorder/i);
  });

  it('grey says it is not a finding of wrongdoing, twice over', () => {
    expect(VERDICTS.grey.lead).toMatch(/[Nn]othing here has been found wrong/);
    expect(VERDICTS.grey.means.join(' ')).toMatch(/not a finding of tampering/i);
    expect(VERDICTS.grey.doesNotMean.join(' ')).toMatch(/[Tt]reating this as an alarm/);
  });

  it('grey never uses alarm words', () => {
    const grey = [VERDICTS.grey.headline, VERDICTS.grey.lead, ...VERDICTS.grey.means].join(' ').toLowerCase();
    for (const w of ['danger', 'warning', 'alert', 'breach', 'attack', 'compromised']) {
      expect(grey, `grey copy contains "${w}"`).not.toContain(w);
    }
  });

  it('red does not claim to know intent or identity', () => {
    expect(VERDICTS.red.means.join(' ')).toMatch(/not a judgement about intent/i);
    expect(VERDICTS.red.doesNotMean.join(' ')).toMatch(/who did it/i);
  });
});

describe('no claim stronger than a test proves', () => {
  it('copy contains no absolute guarantees', () => {
    const copy = allCopy().toLowerCase();
    for (const w of ['tamper-proof', 'tamper proof', 'unhackable', 'guaranteed', 'impossible to',
                     'provably secure', 'military-grade', '100%', 'fully secure', 'immutable']) {
      expect(copy, `copy contains "${w}"`).not.toContain(w);
    }
  });

  it('the only place "complete and unaltered" appears is the green verdict', () => {
    // It is in FALSE_CONFIDENCE_STRINGS precisely so it cannot leak elsewhere.
    expect(FALSE_CONFIDENCE_STRINGS).toContain('complete and unaltered');
    const others = allCopy().replace(VERDICTS.green.headline, '');
    expect(others.toLowerCase()).not.toContain('complete and unaltered');
  });
});

describe('findings are translated, not dumped', () => {
  it('every finding code verify can emit has plain-English copy', () => {
    // Codes are pulled from verify.ts itself so a new one cannot ship untranslated.
    const src = readFileSync(join(process.cwd(), 'src', 'verify.ts'), 'utf8');
    const codes = new Set([...src.matchAll(/code: '([a-z0-9_]+)'/g)].map((m) => m[1]!));
    // Dynamic codes are built from a prefix; cover the prefixes instead.
    const dynamic = ['chain_', 'checkpoint_chain_', 'witness_'];
    const missing = [...codes].filter(
      (c) => FINDING_COPY[c] === undefined && !dynamic.some((d) => c.startsWith(d)),
    );
    expect(missing, `untranslated finding codes: ${missing.join(', ')}`).toEqual([]);
  });

  it('falls back to the technical message rather than inventing one', () => {
    expect(explainFinding('a_code_we_never_wrote', 'raw detail')).toBe('raw detail');
  });

  it('translations avoid jargon too', () => {
    const all = Object.values(FINDING_COPY).join(' ').toLowerCase();
    for (const w of ['merkle', 'sha-256', 'hash chain', 'ed25519', 'rfc 3161']) {
      expect(all, `finding copy contains "${w}"`).not.toContain(w);
    }
  });
});

describe('every screen explains itself', () => {
  it('each screen has a one-liner and a longer explanation', () => {
    for (const [name, s] of Object.entries(SCREENS)) {
      expect(s.what.length, `${name}.what too short`).toBeGreaterThan(30);
      expect(s.detail.length, `${name}.detail too short`).toBeGreaterThan(80);
      expect(s.what.endsWith('.'), `${name}.what should be a sentence`).toBe(true);
    }
  });

  it('the agents screen leads with discovery, which is the point of it', () => {
    expect(SCREENS.agents.what).toMatch(/nobody told us about/i);
    expect(SCREENS.agents.detail).toMatch(/installed and\s+forgot/i);
  });

  it('the evidence screen says what is deliberately excluded', () => {
    expect(SCREENS.evidence.detail).toMatch(/does not include your signing key/i);
  });

  it('the trust screen promises a live check, not a recording', () => {
    expect(SCREENS.trust.detail).toMatch(/on your own log/i);
    expect(SCREENS.trust.detail).toMatch(/not a recording/i);
  });
});
