/**
 * R5 — packaging. The promise is "one command on a machine with nothing set
 * up", so these tests check the things that break that promise: paths resolved
 * from the wrong place, a first run that demands a secret, a shipped tarball
 * missing the interface.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { defaultHome, prepareStart, setupSteps, startBanner } from '../src/quickstart.js';
import { defaultUiDir } from '../src/server.js';
import { EventStore } from '../src/store.js';
import { readCheckpoints } from '../src/checkpoint.js';
import { readWitnessConfig } from '../src/witness-service.js';

let root: string;
beforeEach(() => { root = mkdtempSync(join(tmpdir(), 'orisan-pkg-')); });
afterEach(() => { rmSync(root, { recursive: true, force: true }); });

const home = () => defaultHome(join(root, '.orisan'));

describe('the first run works with nothing set up', () => {
  it('needs no witness, no payload key, no certificate, no config', () => {
    const r = prepareStart({ home: home() });
    expect(r.events).toBeGreaterThan(0);
    expect(existsSync(r.home.logDir)).toBe(true);
    // Nothing was demanded of the user.
    expect(readWitnessConfig(r.home.logDir)).toBeNull();
  });

  it('creates the keys itself, outside the log directory', () => {
    const r = prepareStart({ home: home() });
    expect(existsSync(r.home.signingKey)).toBe(true);
    expect(existsSync(r.home.payloadKey)).toBe(true);
    // The thing verify complains about: a key sitting beside the data it signs.
    expect(r.home.signingKey.startsWith(r.home.logDir)).toBe(false);
    expect(r.home.payloadKey.startsWith(r.home.logDir)).toBe(false);
    expect(existsSync(join(r.home.logDir, 'signing.key'))).toBe(false);
  });

  it('writes keys owner-only', () => {
    const r = prepareStart({ home: home() });
    for (const k of [r.home.signingKey, r.home.payloadKey]) {
      expect(statSync(k).mode & 0o077).toBe(0);
    }
  });

  it('seeds an example so the first screen is not empty, and says it is fabricated', () => {
    const r = prepareStart({ home: home() });
    expect(r.seeded).toBe(true);
    const banner = startBanner(r, 'http://127.0.0.1:4173');
    expect(banner).toMatch(/example session/i);
    expect(banner).toMatch(/fabricated/i);
    expect(banner).toMatch(/rm -rf/);
  });

  it('the seeded example has several runs and no zero-length actions', () => {
    const r = prepareStart({ home: home() });
    const events = EventStore.open(r.home.logDir, { readOnly: true }).store.readAll();
    expect(new Set(events.map((e) => e.session_id)).size).toBeGreaterThan(1);
    // A demo showing 0ms teaches the wrong thing about what is being measured.
    expect(events.filter((e) => e.duration_ms === 0)).toHaveLength(0);
    for (const [, list] of groupBy(events)) {
      const span = Date.parse(list[list.length - 1]!.ts) - Date.parse(list[0]!.ts);
      expect(span).toBeGreaterThan(0);
    }
  });

  it('does not seed over an existing log', () => {
    const first = prepareStart({ home: home() });
    const before = EventStore.open(first.home.logDir, { readOnly: true }).store.count;
    const second = prepareStart({ home: home() });
    expect(second.seeded).toBe(false);
    expect(EventStore.open(second.home.logDir, { readOnly: true }).store.count).toBe(before);
  });

  it('--no-demo leaves an empty log alone', () => {
    const r = prepareStart({ home: home(), noDemo: true });
    expect(r.seeded).toBe(false);
    expect(r.events).toBe(0);
  });

  it('cuts a checkpoint so the timeline has a signed batch', () => {
    const r = prepareStart({ home: home() });
    expect(readCheckpoints(r.home.logDir).length).toBeGreaterThan(0);
  });

  it('is idempotent: running twice changes nothing important', () => {
    const a = prepareStart({ home: home() });
    const keyBefore = readFileSync(a.home.signingKey, 'utf8');
    const b = prepareStart({ home: home() });
    expect(readFileSync(b.home.signingKey, 'utf8')).toBe(keyBefore);
    expect(readCheckpoints(b.home.logDir).length).toBe(readCheckpoints(a.home.logDir).length);
  });
});

describe('it tells the user what green needs, without pretending', () => {
  it('names the witness as the step that makes green possible', () => {
    const r = prepareStart({ home: home() });
    const witnessStep = r.steps.find((s) => /witness/i.test(s.label))!;
    expect(witnessStep.label).toMatch(/what green needs/i);
    expect(witnessStep.done).toBe(false);
    expect(witnessStep.why).toMatch(/deleted from the end/i);
  });

  it('the terminal message says grey is not a warning', () => {
    const banner = startBanner(prepareStart({ home: home() }), 'http://x');
    expect(banner).toMatch(/stay grey until a witness is registered/i);
    expect(banner).toMatch(/not a warning/i);
  });

  it('steps flip to done as things are set up', () => {
    const r = prepareStart({ home: home() });
    const before = setupSteps(r.home).find((s) => s.label.startsWith('Record'))!;
    expect(before.done).toBe(true);
    expect(setupSteps(r.home).find((s) => /timestamp/i.test(s.label))!.done).toBe(false);
  });

  it('every unfinished step explains why it matters and how to do it', () => {
    const r = prepareStart({ home: home() });
    for (const s of r.steps.filter((x) => !x.done)) {
      expect(s.why.length, `${s.label} has no reason`).toBeGreaterThan(40);
      expect(s.command, `${s.label} has no command`).toBeTruthy();
    }
  });
});

describe('paths resolve from the module, not the working directory', () => {
  it('finds the built interface regardless of cwd', () => {
    const uiDir = defaultUiDir();
    expect(existsSync(join(uiDir, 'index.html'))).toBe(true);
  });
});

describe('the installer', () => {
  const raw = readFileSync(join(process.cwd(), 'install.sh'), 'utf8');
  /**
   * Comments stripped: these assertions are about what the script DOES. The
   * header explains why there are no bashisms and no sudo, and matching that
   * prose would fail for saying the right thing.
   */
  const script = raw
    .split('\n')
    .filter((l) => !/^\s*#/.test(l))
    .join('\n');

  it('is POSIX sh, with no bashisms', () => {
    expect(raw.split('\n')[0]).toMatch(/#!\/usr\/bin\/env sh/);
    expect(script).not.toMatch(/\[\[/);
    expect(script).not.toMatch(/\blocal\s+-n\b/);
    expect(script).not.toMatch(/\barray=\(/);
  });

  it('never uses sudo or a global install', () => {
    expect(script).not.toMatch(/sudo/);
    expect(script).not.toMatch(/npm install\s+-g/);
  });

  it('checks for Node and says what to do if it is missing', () => {
    expect(script).toMatch(/MIN_NODE_MAJOR=20/);
    expect(script).toMatch(/nodejs\.org/);
  });

  it('asks for no key, token or account', () => {
    for (const w of ['API_KEY', 'token', 'signup', 'license', 'email']) {
      expect(script.toLowerCase()).not.toContain(w.toLowerCase());
    }
  });

  it('passes shellcheck-style parse under sh -n', () => {
    execFileSync('sh', ['-n', join(process.cwd(), 'install.sh')]);
  });
});

function groupBy(events: { session_id: string; ts: string; duration_ms: number | null }[]) {
  const m = new Map<string, typeof events>();
  for (const e of events) {
    const list = m.get(e.session_id) ?? [];
    list.push(e);
    m.set(e.session_id, list);
  }
  return m;
}
