/**
 * Issue #2a — verify must not hold the log in memory.
 *
 * It used to call `store.readAll()`. Measured before this change:
 *
 *     100,000 events   103 MB on disk   1.6 s   323 MB peak RSS
 *     300,000 events   310 MB on disk   4.0 s   691 MB peak RSS
 *
 * Linear, about 2.3 KB of RSS per event, so a million events is ~2.3 GB and a
 * long-running install eventually reaches the size where its own verifier will
 * not run. Nothing verify does needs random access: the chain walk is
 * sequential and each checkpoint's Merkle root only needs the events in its
 * own range, in order.
 *
 * The assertion is a HARD HEAP CAP rather than a byte figure. Peak RSS depends
 * on when the collector felt like running, which is not a property of the code
 * and would make this test flaky on other machines. "Completes inside 64 MB
 * whatever the log size" is the real claim, it is deterministic, and the last
 * case pins it by showing the old approach dies at exactly that cap.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);
const CLI = join(process.cwd(), 'dist', 'cli.js');
const SMALL = 2_000;
const LARGE = 300_000;
/** Small enough that a materialising verify cannot fit 300k events into it. */
const HEAP_CAP_MB = 64;

let root: string;
let small: string;
let large: string;

async function node(args: string[], capMb?: number): Promise<{ code: number; stdout: string; stderr: string }> {
  const argv = capMb === undefined ? args : [`--max-old-space-size=${capMb}`, ...args];
  try {
    const { stdout, stderr } = await run(process.execPath, argv, { timeout: 600_000, maxBuffer: 64 * 1024 * 1024 });
    return { code: 0, stdout, stderr };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return { code: typeof err.code === 'number' ? err.code : 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

beforeAll(async () => {
  // dist, because a 300k-event run under tsx measures the transpiler too.
  if (!existsSync(CLI)) throw new Error('run `npm run build` before this test');
  root = mkdtempSync(join(tmpdir(), 'orisan-mem-'));
  small = join(root, 'small');
  large = join(root, 'large');
  for (const [dir, n] of [[small, SMALL], [large, LARGE]] as const) {
    await node([CLI, 'demo', dir, '--events', String(n)]);
    await node([CLI, 'checkpoint', dir]);
  }
}, 900_000);

afterAll(() => { if (root) rmSync(root, { recursive: true, force: true }); });

describe('verify streams the log', () => {
  it(`verifies ${LARGE.toLocaleString()} events inside a ${HEAP_CAP_MB} MB heap`, async () => {
    const r = await node([CLI, 'verify', large], HEAP_CAP_MB);
    // exit 2: no witness and no anchor on a demo log. What matters is that it
    // ran to completion and counted every event rather than dying.
    expect(r.stderr + r.stdout).toContain(`events: ${LARGE}`);
    expect(r.stderr + r.stdout).not.toMatch(/heap out of memory|unreadable/);
  }, 900_000);

  it('needs no more heap for a large log than a small one', async () => {
    // The actual claim: the cap that works for 2,000 events also works for
    // 300,000. If verify ever starts materialising again, this fails.
    const smallRun = await node([CLI, 'verify', small], HEAP_CAP_MB);
    const largeRun = await node([CLI, 'verify', large], HEAP_CAP_MB);
    expect(smallRun.stderr + smallRun.stdout).toContain(`events: ${SMALL}`);
    expect(largeRun.stderr + largeRun.stdout).toContain(`events: ${LARGE}`);
  }, 900_000);

  it('retains no more memory for 300,000 events than for 2,000', async () => {
    // LIVE HEAP AFTER A FORCED COLLECTION, not peak RSS.
    //
    // Peak RSS is not flat and is not supposed to be: 300k events churn
    // through vastly more short-lived objects than 2k, so V8 keeps a larger
    // heap to collect less often and the OS reports more. Measured here:
    // 65 MB against 145 MB. That is the allocator's choice, not retention, and
    // asserting a threshold on it would be asserting something that is not a
    // property of this code — it would drift with the node version and the
    // machine. What issue #2 is actually about is whether verify HOLDS the
    // log, and after a forced GC that is 4.8 MB versus 4.0 MB. Flat, and
    // slightly lower for the larger log, which is noise either way.
    const probe = join(root, 'probe.mjs');
    writeFileSync(probe, `
      import { verify } from '${join(process.cwd(), 'dist', 'verify.js')}';
      const r = verify(process.argv[2], { skipOpenssl: true });
      global.gc(); global.gc();
      console.log(JSON.stringify({ events: r.events, live: process.memoryUsage().heapUsed }));
    `);
    const read = async (dir: string): Promise<{ events: number; live: number }> => {
      const out = await node(['--expose-gc', probe, dir]);
      return JSON.parse(out.stdout.trim().split('\n').pop()!) as { events: number; live: number };
    };

    const a = await read(small);
    const b = await read(large);
    expect(a.events).toBe(SMALL);
    expect(b.events).toBe(LARGE);

    // 150x the events. The old readAll() path would be ~150x the live heap;
    // 1.5x is loose enough to absorb GC timing and tight enough that any
    // return to materialising the log fails here immediately.
    const ratio = b.live / a.live;
    expect(ratio, `live heap ratio for ${LARGE / SMALL}x the events was ${ratio.toFixed(2)}`).toBeLessThan(1.5);
  }, 900_000);

  it('the approach it replaced dies at the same cap, which is the point', async () => {
    // A regression guard with teeth: if someone reintroduces readAll() in
    // verify, this is what they will have done.
    const probe = join(root, 'materialise.mjs');
    writeFileSync(probe, `
      import { EventStore } from '${join(process.cwd(), 'dist', 'store.js')}';
      console.log('materialised', EventStore.open(process.argv[2], { readOnly: true }).store.readAll().length);
    `);
    const r = await node([probe, large], HEAP_CAP_MB);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/heap out of memory|Allocation failed/i);
  }, 900_000);
});
