/** R2.4 banner. Tier C: these assertions are the contract on the strings. */
import { describe, it, expect } from 'vitest';
import { FALSE_CONFIDENCE_STRINGS, bannerFor, overclaims } from '../src/banner.js';

const f = (severity: string, code: string, message = 'msg') => ({ severity, code, message });

describe('exit code maps to exactly one tone', () => {
  it('0 is green', () => {
    expect(bannerFor({ exitCode: 0, findings: [] }).tone).toBe('green');
  });
  it('1 is red', () => {
    expect(bannerFor({ exitCode: 1, findings: [f('tampered', 'x')] }).tone).toBe('red');
  });
  it('2 is grey', () => {
    expect(bannerFor({ exitCode: 2, findings: [f('cannot_verify', 'no_witness')] }).tone).toBe('grey');
  });
  it('an unrecognised exit code falls back to grey, never green', () => {
    for (const code of [3, 42, -1, 99]) {
      expect(bannerFor({ exitCode: code, findings: [] }).tone).toBe('grey');
    }
  });
});

describe('green is unreachable except from exit 0', () => {
  it('exit 2 with zero findings is still grey', () => {
    // The dangerous case: nothing looked wrong, so it must be tempting to
    // call it fine. It is not fine; it is unchecked.
    expect(bannerFor({ exitCode: 2, findings: [] }).tone).toBe('grey');
  });

  it('exit 1 with only cannot_verify findings is still red', () => {
    expect(bannerFor({ exitCode: 1, findings: [f('cannot_verify', 'y')] }).tone).toBe('red');
  });
});

describe('confident language is confined to green', () => {
  it('green is the only verdict that claims anything', () => {
    const g = bannerFor({ exitCode: 0, findings: [] });
    expect(g.tone).toBe('green');
    // Green states what was confirmed, and names the witness as the reason.
    expect(g.detail).toMatch(/witness/i);
    expect(g.means.join(' ')).toMatch(/removed/i);
  });

  it('grey and red never say "verified", in any form', () => {
    for (const exitCode of [1, 2]) {
      const b = bannerFor({ exitCode, findings: [f('cannot_verify', 'no_witness')] });
      const text = `${b.headline} ${b.detail}`.toLowerCase();
      expect(text).not.toMatch(/verif/);
    }
  });

  it('no non-green banner contains a false-confidence phrase', () => {
    for (const exitCode of [1, 2, 7]) {
      const b = bannerFor({ exitCode, findings: [f('tampered', 'z')] });
      expect(overclaims(b.tone, `${b.headline} ${b.detail}`)).toEqual([]);
    }
  });
});

describe('grey admits rather than accuses', () => {
  it('leads by saying nothing has been found wrong', () => {
    const b = bannerFor({ exitCode: 2, findings: [f('cannot_verify', 'no_witness')] });
    expect(b.headline).toBe('Cannot prove completeness');
    expect(b.detail).toMatch(/[Nn]othing here has been found wrong/);
    expect(b.detail).toMatch(/cannot rule out/);
  });

  it('spells out that this is not a finding of tampering', () => {
    const b = bannerFor({ exitCode: 2, findings: [f('cannot_verify', 'no_witness')] });
    expect(b.means.join(' ')).toMatch(/not a finding of tampering/i);
    expect(b.doesNotMean.join(' ')).toMatch(/[Tt]reating this as an alarm/);
  });

  it('names the witness as the thing that would change the answer', () => {
    const b = bannerFor({ exitCode: 2, findings: [f('cannot_verify', 'no_witness')] });
    expect(b.means.join(' ')).toMatch(/witness/i);
  });

  it('translates each finding into plain English', () => {
    const b = bannerFor({ exitCode: 2, findings: [f('cannot_verify', 'no_witness', 'raw technical text')] });
    expect(b.findings[0]!.plain).toMatch(/deleted from the end/);
    expect(b.findings[0]!.plain).not.toBe('raw technical text');
  });

  it('always links to the docs', () => {
    for (const exitCode of [0, 1, 2]) {
      expect(bannerFor({ exitCode, findings: [] }).docsHref).toMatch(/^https:\/\//);
    }
  });
});

describe('red names the finding', () => {
  it('leads with the first tampered finding', () => {
    const b = bannerFor({
      exitCode: 1,
      findings: [f('cannot_verify', 'noise', 'ignore me'), f('tampered', 'truncation_detected', 'the real one')],
    });
    expect(b.detail).toMatch(/deleted from the end/);
    expect(b.findings.map((x) => x.code)).toContain('truncation_detected');
  });

  it('falls back to a plain statement if severity labels are missing', () => {
    expect(bannerFor({ exitCode: 1, findings: [] }).detail).toMatch(/A check failed/);
  });

  it('says what red does not mean, so it is not read as an accusation of intent', () => {
    const b = bannerFor({ exitCode: 1, findings: [f('tampered', 'chain_hash_mismatch')] });
    expect(b.doesNotMean.join(' ')).toMatch(/who did it/);
    expect(b.means.join(' ')).toMatch(/not a judgement about intent/);
  });
});

describe('overclaims guard', () => {
  it('flags reassurance in a non-green tone', () => {
    expect(overclaims('grey', 'Integrity verified')).toContain('integrity verified');
    expect(overclaims('red', 'no tampering detected here')).toContain('no tampering detected');
  });
  it('permits it in green', () => {
    expect(overclaims('green', 'Integrity verified')).toEqual([]);
  });
  it('the banned list is non-empty and lowercase', () => {
    expect(FALSE_CONFIDENCE_STRINGS.length).toBeGreaterThan(4);
    for (const s of FALSE_CONFIDENCE_STRINGS) expect(s).toBe(s.toLowerCase());
  });
});
