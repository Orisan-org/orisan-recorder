/**
 * Every URL we ship must point somewhere we own, or somewhere we have a stated
 * reason to reference.
 *
 * This exists because the install command shipped pointing at get.orisan[.]dev —
 * a domain with no DNS record, on a TLD we do not own. It read as plausible and
 * was a false claim on day one. A grep is cheap; the credibility is not.
 *
 * The forbidden domain is spelled with a bracket above and assembled from
 * parts below, so this guard scans every tracked file INCLUDING ITSELF with no
 * exemptions. An allowlisted file is a hole, and the first thing to fall
 * through it would be the string this test is looking for.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Domains that are ours. */
const OURS = ['orisan.org'];

/**
 * Third parties we reference on purpose. Each needs a reason, because an
 * unexplained entry here is how the allowlist stops meaning anything.
 */
const THIRD_PARTY: { domain: string; why: string }[] = [
  { domain: 'freetsa.org', why: 'default timestamp authority; the URL is configurable' },
  { domain: 'npmjs.com', why: 'where the package is published' },
  { domain: 'registry.npmjs.org', why: 'npm registry, in lockfiles' },
  { domain: 'github.com', why: 'source repository' },
  { domain: 'nodejs.org', why: 'told to the user by install.sh when Node is missing' },
  { domain: 'api.anthropic.com', why: 'example upstream in the tap docs; supplied by the user' },
  { domain: 'api.openai.com', why: 'example upstream in the tap docs; supplied by the user' },
];

/** Addresses that can never leave the machine or resolve at all. */
function isNonRoutable(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '::1' || h === '0.0.0.0' || /^127\./.test(h)) return true;
  // RFC 2606 / RFC 6761 reserved: cannot be registered by anyone.
  if (/\.(invalid|test|example|localhost)$/.test(h)) return true;
  if (h === 'example.com' || h === 'example.org' || h === 'example.net') return true;
  // Private ranges, used in test fixtures.
  if (/^10\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  // A bare token like "x" in a test URL has no TLD and cannot resolve.
  if (!h.includes('.')) return true;
  return false;
}

function allowed(host: string): boolean {
  const h = host.toLowerCase();
  if (isNonRoutable(h)) return true;
  if (OURS.some((d) => h === d || h.endsWith(`.${d}`))) return true;
  if (THIRD_PARTY.some((t) => h === t.domain || h.endsWith(`.${t.domain}`))) return true;
  return false;
}

/** Tracked files, minus lockfiles (dependency metadata, not our URLs). */
function trackedFiles(): string[] {
  return execFileSync('git', ['ls-files'], { cwd: process.cwd(), encoding: 'utf8' })
    .split('\n')
    .filter((f) => f.length > 0)
    .filter((f) => !/(^|\/)package-lock\.json$/.test(f))
    .filter((f) => !/^ui\/dist\//.test(f));
}

describe('no URL points at a domain we do not own', () => {
  it('every host in every tracked file is ours, justified, or unroutable', () => {
    const offenders: string[] = [];
    for (const file of trackedFiles()) {
      let text: string;
      try { text = readFileSync(join(process.cwd(), file), 'utf8'); } catch { continue; }
      for (const m of text.matchAll(/https?:\/\/([a-zA-Z0-9._:[\]-]+)/g)) {
        const host = (m[1] ?? '').replace(/:\d+$/, '').replace(/\.$/, '');
        if (!allowed(host)) offenders.push(`${file}: ${host}`);
      }
    }
    expect(offenders, `URLs on domains we do not own:\n  ${offenders.join('\n  ')}`).toEqual([]);
  });

  it('the domain we do not own never comes back', () => {
    // Assembled so this file does not itself contain the string.
    const forbidden = new RegExp(`orisan${'\\'}.dev`, 'i');
    const hits: string[] = [];
    for (const file of trackedFiles()) {
      let text: string;
      try { text = readFileSync(join(process.cwd(), file), 'utf8'); } catch { continue; }
      if (forbidden.test(text)) hits.push(file);
    }
    expect(hits, `we do not own that domain; found in: ${hits.join(', ')}`).toEqual([]);
  });

  it('the install script points at orisan.org and nowhere else for our own assets', () => {
    const script = readFileSync(join(process.cwd(), 'install.sh'), 'utf8');
    expect(script).toMatch(/https:\/\/orisan\.org\/install\.sh/);
    for (const m of script.matchAll(/https?:\/\/([a-zA-Z0-9._-]+)/g)) {
      const host = (m[1] ?? '').replace(/\.$/, '');
      expect(allowed(host), `install.sh references ${host}`).toBe(true);
    }
  });

  it('every third-party entry carries a reason', () => {
    for (const t of THIRD_PARTY) {
      expect(t.why.length, `${t.domain} has no stated reason`).toBeGreaterThan(15);
    }
  });
});

describe('the one-liner is not claimed until it is live', () => {
  const readme = readFileSync(join(process.cwd(), 'README.md'), 'utf8');

  it('the README leads with the path that works today', () => {
    const checkout = readme.indexOf('from a checkout');
    const curl = readme.indexOf('curl -fsSL');
    expect(checkout).toBeGreaterThan(-1);
    expect(checkout, 'the working path must come first').toBeLessThan(curl);
  });

  it('the curl line is marked not live', () => {
    const line = readme.split('\n').find((l) => l.includes('curl -fsSL'))!;
    expect(line).toMatch(/not live yet/i);
  });

  it('install.sh says plainly that it is not published', () => {
    expect(readFileSync(join(process.cwd(), 'install.sh'), 'utf8')).toMatch(/NOT YET PUBLISHED/);
  });
});
