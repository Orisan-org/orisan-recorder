/**
 * R3 — the model-call tap.
 *
 * The fail-open tests come first because this is where a defect breaks
 * someone's real work: a tool call that fails is annoying, a model call that
 * fails stops the agent dead.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Recorder } from '../src/recorder.js';
import { EventStore } from '../src/store.js';
import { PAYLOAD_DIRNAME, generateKeyFile, openPayload } from '../src/payloads.js';
import {
  isModelCall, providerFor, readDecisionJson, readDecisionStream, readRequestFacts, startTap,
  type CapturedContext, type TapHandle,
} from '../src/tap.js';
import { startFakeModelApi, type FakeApi } from './fixtures/fake-model-api.js';

let dir: string; let keyDir: string; let api: FakeApi; let tap: TapHandle | null = null;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'tap-'));
  keyDir = mkdtempSync(join(tmpdir(), 'tap-key-'));
  api = await startFakeModelApi();
});
afterEach(async () => {
  if (tap) { await tap.close(); tap = null; }
  await api.close();
  for (const d of [dir, keyDir]) rmSync(d, { recursive: true, force: true });
});

function recorder(): Recorder {
  return Recorder.open(dir, {
    fsync: false, anchor: { enabled: false }, submitToWitness: false,
    signingKeyPath: join(keyDir, 'signing.key'),
  });
}
const payloadKey = () => generateKeyFile(join(keyDir, 'payload.key'));

const ANTHROPIC_BODY = JSON.stringify({
  model: 'claude-sonnet-4-5',
  system: 'You are a fake assistant with a secret: CANARY-SYSTEM-PROMPT',
  messages: [{ role: 'user', content: 'CANARY-USER-MESSAGE about a fake invoice' }],
  tools: [{ name: 'fake_lookup' }],
});

async function call(body = ANTHROPIC_BODY, path = '/v1/messages'): Promise<Response> {
  return fetch(`http://127.0.0.1:${tap!.port}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer FAKE-KEY' },
    body,
  });
}

const settle = () => new Promise((r) => setTimeout(r, 250));
const events = () => EventStore.open(dir, { readOnly: true }).store.readAll();

// ---------------------------------------------------------------------------

describe('FAIL OPEN — the agent keeps working whatever the recorder does', () => {
  it('proxies faithfully with no recorder at all', async () => {
    tap = await startTap({ upstream: api.url, port: 0, recorder: null, log: () => undefined });
    const res = await call();
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('fake completion text');
    // The upstream saw the real request, headers included.
    expect(api.seen[0]!.auth).toBe('Bearer FAKE-KEY');
    expect(api.seen[0]!.body).toBe(ANTHROPIC_BODY);
  });

  it('proxies when sealing throws on every call', async () => {
    // A key file that will not seal: the capture path fails, the call must not.
    const broken = { ...payloadKey(), public_key: 'not-base64-at-all' };
    tap = await startTap({
      upstream: api.url, port: 0, recorder: recorder(),
      payloadKey: broken, logDir: dir, log: () => undefined,
    });
    const res = await call();
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('fake completion text');

    await settle();
    // The event is still recorded, without context, and says why.
    const e = events().find((x) => x.kind === 'model_call');
    expect(e).toBeDefined();
    expect(e!.payload_ref).toBeNull();
    expect(e!.outcome).toMatch(/sealing failed/);
  });

  it('proxies when the recorder itself throws on every record', async () => {
    const rec = recorder();
    // Simulate a recorder that is broken in a way the tap cannot anticipate.
    (rec as unknown as { record: () => Promise<never> }).record = () => Promise.reject(new Error('disk on fire'));
    tap = await startTap({
      upstream: api.url, port: 0, recorder: rec, payloadKey: payloadKey(), logDir: dir, log: () => undefined,
    });
    const res = await call();
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('fake completion text');
  });

  it('a streaming response is not held back by capture', async () => {
    tap = await startTap({
      upstream: api.url, port: 0, recorder: recorder(), payloadKey: payloadKey(), logDir: dir, log: () => undefined,
    });
    const res = await call(JSON.stringify({ ...JSON.parse(ANTHROPIC_BODY), stream: true }));
    const text = await res.text();
    expect(text).toContain('data: ');
    expect(text).toContain('[DONE]');
  });

  it('an upstream error reaches the agent unchanged, not swallowed', async () => {
    await api.close();
    tap = await startTap({
      upstream: api.url, port: 0, recorder: recorder(), payloadKey: payloadKey(), logDir: dir, log: () => undefined,
    });
    const res = await call();
    expect(res.status).toBe(502);
    expect(await res.text()).toMatch(/orisan_tap_upstream_error/);
  });
});

describe('EVERY CAPTURED CONTEXT IS ENCRYPTED', () => {
  it('the prompt never appears in the event log', async () => {
    tap = await startTap({
      upstream: api.url, port: 0, recorder: recorder(), payloadKey: payloadKey(), logDir: dir, log: () => undefined,
    });
    await call();
    await settle();

    const raw = readdirSync(dir)
      .filter((f) => f.startsWith('events-'))
      .map((f) => readFileSync(join(dir, f), 'utf8')).join('');
    expect(raw).not.toContain('CANARY-SYSTEM-PROMPT');
    expect(raw).not.toContain('CANARY-USER-MESSAGE');
    expect(raw).not.toContain('fake completion text');
  });

  it('the prompt never appears in the payload blob either', async () => {
    const key = payloadKey();
    tap = await startTap({ upstream: api.url, port: 0, recorder: recorder(), payloadKey: key, logDir: dir, log: () => undefined });
    await call();
    await settle();

    const blobs = readdirSync(join(dir, PAYLOAD_DIRNAME));
    expect(blobs).toHaveLength(1);
    const bytes = readFileSync(join(dir, PAYLOAD_DIRNAME, blobs[0]!));
    expect(bytes.includes(Buffer.from('CANARY-SYSTEM-PROMPT'))).toBe(false);
    expect(bytes.includes(Buffer.from('CANARY-USER-MESSAGE'))).toBe(false);
  });

  it('but the holder of the key can read the full context and decision', async () => {
    const key = payloadKey();
    tap = await startTap({ upstream: api.url, port: 0, recorder: recorder(), payloadKey: key, logDir: dir, log: () => undefined });
    await call();
    await settle();

    const e = events().find((x) => x.kind === 'model_call')!;
    expect(e.payload_ref).toMatch(/^[0-9a-f]{64}$/);
    const ctx = JSON.parse(openPayload(dir, key, e.payload_ref!).toString('utf8')) as CapturedContext;

    // Full context in.
    const req = ctx.request as { system: string; messages: { content: string }[] };
    expect(req.system).toContain('CANARY-SYSTEM-PROMPT');
    expect(req.messages[0]!.content).toContain('CANARY-USER-MESSAGE');
    // Decision out.
    const resp = ctx.response as { content: { type: string; name?: string }[]; stop_reason: string };
    expect(resp.stop_reason).toBe('tool_use');
    expect(resp.content.some((b) => b.type === 'tool_use' && b.name === 'fake_lookup')).toBe(true);
  });

  it('with no key there is no capture — never a plaintext fallback', async () => {
    tap = await startTap({ upstream: api.url, port: 0, recorder: recorder(), payloadKey: null, logDir: dir, log: () => undefined });
    await call();
    await settle();

    const e = events().find((x) => x.kind === 'model_call')!;
    expect(e.payload_ref).toBeNull();
    expect(e.outcome).toMatch(/no payload key/);
    expect(readdirSync(dir)).not.toContain(PAYLOAD_DIRNAME);
  });

  it('an oversized context is skipped rather than truncated into the log', async () => {
    tap = await startTap({
      upstream: api.url, port: 0, recorder: recorder(), payloadKey: payloadKey(),
      logDir: dir, maxCaptureBytes: 200, log: () => undefined,
    });
    await call();
    await settle();
    const e = events().find((x) => x.kind === 'model_call')!;
    expect(e.payload_ref).toBeNull();
    expect(e.outcome).toMatch(/size cap/);
  });
});

describe('what the event says about a model call', () => {
  it('records model, stop reason, tool calls and duration', async () => {
    tap = await startTap({ upstream: api.url, port: 0, recorder: recorder(), payloadKey: payloadKey(), logDir: dir, log: () => undefined });
    await call();
    await settle();

    const e = events().find((x) => x.kind === 'model_call')!;
    expect(e.kind).toBe('model_call');
    expect(e.target).toBe('claude-sonnet-4-5');
    expect(e.outcome).toMatch(/tool_use -> fake_lookup/);
    expect(e.args_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(e.duration_ms).toBeGreaterThanOrEqual(0);
    expect(e.actor.agent_id).toBe('spiffe://orisan/model/anthropic');
  });

  it('records a streaming call, reconstructing the decision from SSE', async () => {
    tap = await startTap({ upstream: api.url, port: 0, recorder: recorder(), payloadKey: payloadKey(), logDir: dir, log: () => undefined });
    await call(JSON.stringify({ ...JSON.parse(ANTHROPIC_BODY), stream: true }));
    await settle();
    const e = events().find((x) => x.kind === 'model_call')!;
    expect(e.outcome).toMatch(/end_turn/);
  });

  it('records an OpenAI-shaped call', async () => {
    tap = await startTap({ upstream: api.url, port: 0, recorder: recorder(), payloadKey: payloadKey(), logDir: dir, log: () => undefined });
    await call(JSON.stringify({ model: 'gpt-fake', messages: [{ role: 'user', content: 'hi' }] }), '/v1/chat/completions');
    await settle();
    const e = events().find((x) => x.kind === 'model_call')!;
    expect(e.target).toBe('gpt-fake');
    expect(e.outcome).toMatch(/stop/);
    expect(e.actor.agent_id).toBe('spiffe://orisan/model/openai');
  });

  it('does not record non-model paths', async () => {
    tap = await startTap({ upstream: api.url, port: 0, recorder: recorder(), payloadKey: payloadKey(), logDir: dir, log: () => undefined });
    await fetch(`http://127.0.0.1:${tap.port}/health`);
    await settle();
    expect(events().filter((e) => e.kind === 'model_call')).toHaveLength(0);
  });

  it('model calls join the same chain as tool calls', async () => {
    const rec = recorder();
    tap = await startTap({ upstream: api.url, port: 0, recorder: rec, payloadKey: payloadKey(), logDir: dir, log: () => undefined });
    await rec.record({
      actor: { human: 'a', agent_id: 'spiffe://x', tool: 't' }, kind: 'tool_call',
      target: 'fs.read', args_digest: null, payload_ref: null, outcome: 'ok', duration_ms: 1,
    });
    await call();
    await settle();

    const all = events();
    expect(all.map((e) => e.kind)).toContain('model_call');
    expect(all.map((e) => e.kind)).toContain('tool_call');
    // One session, one chain.
    expect(new Set(all.map((e) => e.session_id)).size).toBe(1);
    expect(EventStore.open(dir, { readOnly: true }).store.verifyChainOnly()).toEqual([]);
  });
});

describe('parsers', () => {
  it('classifies providers and model paths', () => {
    expect(providerFor('/v1/messages', 'https://api.anthropic.com')).toBe('anthropic');
    expect(providerFor('/v1/chat/completions', 'https://api.openai.com')).toBe('openai');
    expect(isModelCall('/v1/messages')).toBe(true);
    expect(isModelCall('/health')).toBe(false);
  });

  it('reads request facts without returning any content', () => {
    const f = readRequestFacts(ANTHROPIC_BODY);
    expect(f.model).toBe('claude-sonnet-4-5');
    expect(f.messageCount).toBe(1);
    expect(f.toolCount).toBe(1);
    expect(f.systemChars).toBeGreaterThan(0);
    expect(JSON.stringify(f)).not.toContain('CANARY');
  });

  it('survives a body that is not JSON', () => {
    expect(readRequestFacts('<html>').model).toBeNull();
    expect(readDecisionJson('nope', 'anthropic').stopReason).toBeNull();
    expect(readDecisionStream('garbage\ndata: {oops\n', 'anthropic').textChars).toBe(0);
  });
});
