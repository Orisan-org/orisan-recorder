/**
 * The README's documented path, walked end to end as a first-time user.
 *
 * Two defects got past a green suite and a hand review, and both were found
 * only by installing the thing from scratch and following the instructions:
 *
 *  - `witness register <dir>` created a SECOND signing key inside the log
 *    directory, so a log signed with the key `start` had made was checked
 *    against a different one and the banner turned RED on an untouched log.
 *    A false accusation of tampering is the worst output this product has.
 *  - `start` never passed a TSA CA to the server, so the banner could not go
 *    green however much the user did — while every screen in the interface is
 *    organised around reaching green.
 *
 * Neither was visible from unit tests of the pieces, because both lived in how
 * the CLI wires its arguments. So this drives the real CLI as a subprocess,
 * with an empty HOME, in the order the README gives.
 *
 * It is offline. The timestamp authority is the local fixture, and the witness
 * is the local service bound to this machine's LAN address rather than
 * loopback — verify discounts a loopback witness, correctly, so a green verdict
 * is unreachable with one.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtempSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { DEFAULT_WITNESS_URL } from '../src/witness-service.js';
import { startLocalTsa, startLocalTsaHttp, type LocalTsa, type LocalTsaServer } from './fixtures/tsa-fixture.js';
import { startWitness, witnessAvailable, nonLoopbackAddress, type LiveWitness } from './fixtures/witness-fixture.js';

const run = promisify(execFile);
const TSX = join(process.cwd(), 'node_modules', '.bin', 'tsx');
const CLI = join(process.cwd(), 'src', 'cli.ts');

/** The CLI as a user runs it, with a HOME that has never seen this tool. */
async function cli(home: string, args: string[]): Promise<{ code: number; out: string }> {
  try {
    const r = await run(TSX, [CLI, ...args], {
      env: { ...process.env, HOME: home, USERPROFILE: home },
      maxBuffer: 32 * 1024 * 1024,
    });
    return { code: 0, out: `${r.stdout}${r.stderr}` };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return { code: err.code ?? 1, out: `${err.stdout ?? ''}${err.stderr ?? ''}` };
  }
}

describe('the witness the documentation tells you to use', () => {
  // The URL was in exactly one place a reader never looks, and the command the
  // interface offered had a placeholder where it belonged. These four are the
  // places a first-time user actually meets it; drift in any of them puts the
  // reader back where they started.
  it('is named in every place a user is told to register one', async () => {
    expect(DEFAULT_WITNESS_URL).toBe('https://witness.orisan.org');

    const { readFileSync } = await import('node:fs');
    expect(readFileSync('README.md', 'utf8')).toContain(DEFAULT_WITNESS_URL);
    expect(readFileSync('ui/src/Tour.tsx', 'utf8')).toContain(DEFAULT_WITNESS_URL);

    const { setupSteps, defaultHome } = await import('../src/quickstart.js');
    const step = setupSteps(defaultHome(join(tmpdir(), 'orisan-none'))).find((s) => /witness/i.test(s.label));
    expect(step?.why).toContain(DEFAULT_WITNESS_URL);
    // The command must be runnable as printed: no placeholder to fill in.
    expect(step?.command ?? '').not.toMatch(/<[^>]*>/);

    const home = mkdtempSync(join(tmpdir(), 'orisan-help-'));
    try {
      const help = await cli(home, ['witness', '--help']);
      expect(help.out).toContain(DEFAULT_WITNESS_URL);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }, 60_000);
});

const witnessSuite = witnessAvailable ? describe : describe.skip;

witnessSuite('a first-time user following the README reaches a green banner', () => {
  let home: string; let tsa: LocalTsa; let tsaHttp: LocalTsaServer; let witness: LiveWitness | null = null;
  let logDir = '';

  beforeAll(async () => {
    home = mkdtempSync(join(tmpdir(), 'orisan-readme-home-'));
    tsa = startLocalTsa();
    tsaHttp = await startLocalTsaHttp(tsa);
    witness = await startWitness({ reachable: true });
  }, 120_000);

  afterAll(async () => {
    if (witness) await witness.stop();
    await tsaHttp.close();
    rmSync(home, { recursive: true, force: true });
  });

  it('has an address that verify will not discount as loopback', () => {
    // If this fails the rest cannot mean anything: a loopback witness can never
    // produce green, so a "green" assertion below would be testing nothing.
    expect(nonLoopbackAddress()).not.toBeNull();
    expect(witness!.url).not.toMatch(/127\.0\.0\.1|localhost/);
  });

  it('creates the signing key OUTSIDE the log directory, and keeps it there', async () => {
    const r = await cli(home, ['demo', join(home, '.orisan', 'logs', 'default'), '--events', '6']);
    expect(r.code).toBe(0);
    logDir = join(home, '.orisan', 'logs', 'default');

    // Every command that signs must agree on one key. When they did not, the
    // log was signed by one and verified against another.
    for (const args of [
      ['checkpoint', logDir],
      ['witness', 'register', logDir, '--url', witness!.url],
    ]) {
      const step = await cli(home, args);
      expect(step.code, `${args.join(' ')} failed: ${step.out}`).toBe(0);
      expect(
        existsSync(join(logDir, 'signing.key')),
        `${args[0]} wrote a private signing key beside the data; verify will read the wrong key `
        + 'and report an untouched log as tampered',
      ).toBe(false);
    }
    expect(existsSync(join(home, '.orisan', 'keys', 'signing.key'))).toBe(true);
  }, 180_000);

  it('reaches a clean verdict, and never calls the untouched log tampered', async () => {
    const anchor = await cli(home, ['anchor', logDir, '--tsa', tsaHttp.url]);
    expect(anchor.code, anchor.out).toBe(0);

    const submit = await cli(home, ['witness', 'submit', logDir]);
    expect(submit.code, submit.out).toBe(0);

    const verified = await cli(home, ['verify', logDir, '--tsa-ca', tsa.caFile]);
    // The specific regression: an untouched log must never be called altered.
    expect(verified.out).not.toMatch(/TAMPERED/);
    expect(verified.out).toMatch(/CLEAN/);
    expect(verified.code, `a log built by following the README did not verify clean:\n${verified.out}`).toBe(0);
  }, 180_000);

  it('shows a GREEN banner in the interface', async () => {
    // The interface is organised entirely around reaching green. Asserting the
    // exit code is not enough: `start` has to hand the server the CA, and when
    // it did not, verify was clean on the command line while the banner stayed
    // grey forever.
    const port = 41730 + (process.pid % 900);
    const child = execFile(TSX, [CLI, 'start', '--tsa-ca', tsa.caFile, '--port', String(port)], {
      env: { ...process.env, HOME: home, USERPROFILE: home },
      maxBuffer: 32 * 1024 * 1024,
    }, () => undefined);
    try {
      const base = `http://127.0.0.1:${port}`;
      let status: { banner?: { tone?: string; headline?: string } } | null = null;
      for (let i = 0; i < 120 && status === null; i++) {
        try {
          const res = await fetch(`${base}/api/status`);
          if (res.ok) status = await res.json() as typeof status;
        } catch { /* not up yet */ }
        if (status === null) await new Promise((r) => setTimeout(r, 500));
      }
      expect(status, 'the interface never came up').not.toBeNull();
      expect(
        status!.banner?.tone,
        `a user who followed the README got a ${status!.banner?.tone} banner: `
        + `"${status!.banner?.headline}". The documented path must reach green.`,
      ).toBe('green');
      expect(status!.banner?.tone).not.toBe('red');
    } finally {
      child.kill('SIGTERM');
    }
  }, 180_000);
});
