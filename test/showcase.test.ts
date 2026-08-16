/**
 * `orisan-rec showcase` — the demo, run offline against real local services.
 *
 * A local witness over a real socket and a local RFC 3161 authority over a
 * real socket, so the identical script runs in CI without touching
 * witness.orisan.org or freetsa.org. The CLI is spawned exactly as the command
 * spawns it, so this exercises the real subprocesses rather than a stub.
 *
 * The assertion that matters is the SHAPE of the run: clean at step 5, fooled
 * at step 7, caught at step 8. If those ever stop holding, the demo is telling
 * an audience something untrue and must fail loudly instead.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runShowcase, type ShowcaseResult } from '../src/showcase.js';
import { startLocalTsa, startLocalTsaHttp, type LocalTsa, type LocalTsaServer } from './fixtures/tsa-fixture.js';
import { startWitness, type LiveWitness } from './fixtures/witness-fixture.js';

let tsa: LocalTsa;
let tsaHttp: LocalTsaServer;
let witness: LiveWitness;
let result: ShowcaseResult;
let transcript = '';
let dir: string;

const TSX = join(process.cwd(), 'node_modules', '.bin', 'tsx');
const CLI = join(process.cwd(), 'src', 'cli.ts');

beforeAll(async () => {
  tsa = startLocalTsa();
  tsaHttp = await startLocalTsaHttp(tsa);
  witness = await startWitness();
  dir = mkdtempSync(join(tmpdir(), 'showcase-test-'));

  result = await runShowcase({
    dir,
    cli: [TSX, CLI],
    witnessUrl: witness.url,
    tsaUrl: tsaHttp.url,
    tsaCaFile: tsa.caFile,
    pauseMs: 0,
    plain: true,
    keep: true,
    out: (s) => { transcript += s; },
  });
}, 240_000);

afterAll(async () => {
  await tsaHttp.close();
  await witness.stop();
  tsa.cleanup();
  rmSync(dir, { recursive: true, force: true });
});

describe('the run succeeds end to end', () => {
  it('every step behaved as the script asserts', () => {
    expect(result.failures, result.failures.join('; ')).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it('runs all nine steps in order', () => {
    for (let n = 1; n <= 9; n++) {
      expect(transcript, `step ${n} missing`).toContain(`-- ${n}.`);
    }
  });
});

describe('the three lines the demo exists for', () => {
  it('step 5: refuses CLEAN here, because the test witness is on this machine', () => {
    // The fixture witness necessarily runs on loopback, and verify will not
    // count a witness the operator could delete. So the offline run asserts
    // exit 2 and an explicit explanation, rather than pretending to be green.
    // The CLEAN path is exercised by running the showcase against the hosted
    // witness — see the committed asciinema recording.
    const step = result.steps.find((s) => s.title === 'verify (clean)')!;
    expect(step.exitCode).toBe(2);
    expect(step.ok, 'the run should expect 2 for a local witness').toBe(true);
    expect(transcript).toMatch(/that witness runs on this machine/i);
    expect(transcript).toMatch(/rather than CLEAN/);
  });

  it('step 7: the chain-only check is fooled and returns 0', () => {
    const step = result.steps.find((s) => s.title === 'chain-only (fooled)')!;
    expect(step.exitCode).toBe(0);
    expect(transcript).toContain('chain intact');
  });

  it('step 8: the full check catches it, exit 1, naming truncation', () => {
    const step = result.steps.find((s) => s.title === 'verify (tampered)')!;
    expect(step.exitCode).toBe(1);
    expect(transcript).toContain('truncation_detected');
  });
});

describe('the truncation leaves a plausible log, not an empty one', () => {
  it('deletes only the last batch', () => {
    // With one checkpoint, "delete the tail" removes everything, and an empty
    // log is obviously wrong — it would demonstrate nothing.
    expect(transcript).toMatch(/deleted \d+ actions/);
    const remaining = /(\d+) actions remain/.exec(transcript);
    expect(remaining).not.toBeNull();
    expect(Number.parseInt(remaining![1]!, 10)).toBeGreaterThan(0);
  });

  it('commits two batches before attacking, so a prefix survives', () => {
    expect(result.steps.filter((s) => s.title.startsWith('checkpoint'))).toHaveLength(2);
    expect(result.steps.filter((s) => s.title.startsWith('submit'))).toHaveLength(2);
  });
});

describe('it does not overclaim', () => {
  it('labels the recorded session as fabricated', () => {
    expect(transcript).toMatch(/fabricated session, labelled as such/i);
    expect(transcript).toMatch(/no real agent is being driven/i);
  });

  it('says openssl does the timestamp check, not us', () => {
    expect(transcript).toMatch(/openssl checks the timestamp, not us/i);
  });

  it('closes on what the witness caught that the log could not', () => {
    expect(transcript).toContain('The log said it was fine. The witness said a checkpoint is missing.');
  });
});

describe('a failing step fails the run', () => {
  it('reports SHOWCASE FAILED and a non-zero result when a step misbehaves', async () => {
    // Point at a witness that is not there. Registration fails, and the run
    // must say so rather than continuing to a reassuring ending.
    const badDir = mkdtempSync(join(tmpdir(), 'showcase-fail-'));
    let text = '';
    try {
      const bad = await runShowcase({
        dir: badDir,
        cli: [TSX, CLI],
        witnessUrl: 'http://127.0.0.1:1',
        tsaUrl: tsaHttp.url,
        tsaCaFile: tsa.caFile,
        pauseMs: 0,
        plain: true,
        keep: true,
        out: (s) => { text += s; },
      });
      expect(bad.ok).toBe(false);
      expect(bad.failures.length).toBeGreaterThan(0);
      expect(text).toContain('SHOWCASE FAILED');
    } finally {
      rmSync(badDir, { recursive: true, force: true });
    }
  }, 240_000);
});

describe('it cleans up after itself', () => {
  it('leaves no signing key behind in a temp directory', () => {
    const strays = existsSync(tmpdir())
      ? require('node:fs').readdirSync(tmpdir()).filter((f: string) => f.startsWith('orisan-showcase-key-'))
      : [];
    expect(strays).toEqual([]);
  });
});
