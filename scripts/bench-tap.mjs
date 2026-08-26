/**
 * Measure what the tap costs a model call.
 *
 * The README quotes an overhead figure. A quoted number nobody can reproduce is
 * indistinguishable from a number somebody made up, so this is the harness that
 * produces it. Run it and replace the figure with what your machine says.
 *
 *   npm run build && node scripts/bench-tap.mjs [--calls 300] [--context-kb 80]
 *
 * Method: an identical request is issued N times straight at a local upstream,
 * then N times through the tap at the same upstream. Overhead is the difference
 * between the two distributions, reported at the median and p95. The upstream
 * is local so its own latency is small and common to both arms; what is left is
 * the proxy hop plus whatever the recorder does on the request path.
 *
 * Both arms run buffered and streaming, because the tap handles them by
 * different code paths — streaming has to tee the body as it passes.
 */
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { startTap } from '../dist/tap.js';
import { Recorder } from '../dist/recorder.js';
import { generateKeyFile } from '../dist/payloads.js';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : Number(process.argv[i + 1]);
};
const CALLS = arg('calls', 300);
const CONTEXT_KB = arg('context-kb', 80);
const WARMUP = 30;

/** A local stand-in for the provider. Constant work, so it cancels out. */
function upstream() {
  return new Promise((resolve) => {
    const srv = createServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const streaming = JSON.parse(Buffer.concat(chunks).toString() || '{}').stream === true;
        if (!streaming) {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            id: 'msg_bench', model: 'claude-sonnet-4-5', role: 'assistant',
            content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn',
            usage: { input_tokens: 1000, output_tokens: 5 },
          }));
          return;
        }
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        for (const ev of [
          { type: 'message_start', message: { id: 'msg_bench', model: 'claude-sonnet-4-5', usage: { input_tokens: 1000, output_tokens: 0 } } },
          { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'ok' } },
          { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 5 } },
          { type: 'message_stop' },
        ]) res.write(`event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`);
        res.end();
      });
    });
    srv.listen(0, '127.0.0.1', () => resolve({
      url: `http://127.0.0.1:${srv.address().port}`,
      close: () => new Promise((r) => srv.close(r)),
    }));
  });
}

const body = (streaming) => {
  // Pad the user turn so the request carries a realistic context.
  const filler = 'x'.repeat(CONTEXT_KB * 1024);
  return JSON.stringify({
    model: 'claude-sonnet-4-5',
    ...(streaming ? { stream: true } : {}),
    messages: [{ role: 'user', content: filler }],
  });
};

async function timeCalls(base, payload, n) {
  const samples = [];
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    const res = await fetch(`${base}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer BENCH' },
      body: payload,
    });
    await res.arrayBuffer();               // include reading the full response
    samples.push(performance.now() - t0);
  }
  return samples;
}

const pct = (xs, p) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
};

async function arm(label, streaming, api, tapBase) {
  const payload = body(streaming);
  await timeCalls(api.url, payload, WARMUP);
  const direct = await timeCalls(api.url, payload, CALLS);
  await timeCalls(tapBase, payload, WARMUP);
  const tapped = await timeCalls(tapBase, payload, CALLS);
  const d = { p50: pct(direct, 50), p95: pct(direct, 95) };
  const t = { p50: pct(tapped, 50), p95: pct(tapped, 95) };
  console.log(
    `${label.padEnd(10)} direct p50 ${d.p50.toFixed(2)}ms p95 ${d.p95.toFixed(2)}ms  |  ` +
    `tapped p50 ${t.p50.toFixed(2)}ms p95 ${t.p95.toFixed(2)}ms  |  ` +
    `OVERHEAD p50 +${(t.p50 - d.p50).toFixed(2)}ms p95 +${(t.p95 - d.p95).toFixed(2)}ms`,
  );
  return { p50: t.p50 - d.p50, p95: t.p95 - d.p95 };
}

const dir = mkdtempSync(join(tmpdir(), 'bench-log-'));
const keyDir = mkdtempSync(join(tmpdir(), 'bench-key-'));
const api = await upstream();
const recorder = Recorder.open(dir, {
  fsync: false, anchor: { enabled: false }, submitToWitness: false,
  signingKeyPath: join(keyDir, 'signing.key'),
});
const tap = await startTap({
  upstream: api.url,
  port: 0,
  recorder,
  payloadKey: generateKeyFile(join(keyDir, 'payload.key')),
  logDir: dir,
  log: () => {},
});
const tapBase = `http://127.0.0.1:${tap.port}`;

console.log(`${CALLS} calls, ${CONTEXT_KB}KB context, local upstream, ${WARMUP} warmup\n`);
const buffered = await arm('buffered', false, api, tapBase);
const streaming = await arm('streaming', true, api, tapBase);

console.log(
  `\nREADME line: median +${buffered.p50.toFixed(2)}ms buffered, ` +
  `+${streaming.p50.toFixed(2)}ms streaming ` +
  `(p95 +${buffered.p95.toFixed(1)}ms / +${streaming.p95.toFixed(1)}ms).`,
);

await tap.close();
await recorder.close?.();
await api.close();
for (const d of [dir, keyDir]) rmSync(d, { recursive: true, force: true });
