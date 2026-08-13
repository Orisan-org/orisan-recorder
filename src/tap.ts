/**
 * R3 — the relay tap: model calls.
 *
 * An HTTP reverse proxy between an agent and its model provider. The agent
 * points ANTHROPIC_BASE_URL / OPENAI_BASE_URL at us; we forward the request
 * byte-for-byte upstream and stream the response straight back, recording a
 * `model_call` event as a side effect.
 *
 * TWO RULES, both non-negotiable, both tested.
 *
 * 1. FAIL OPEN. Every capture path is wrapped. If the recorder cannot open,
 *    if sealing fails, if this file has a bug — the request still reaches the
 *    model and the response still reaches the agent. This is where a defect
 *    breaks someone's real work, so the proxy path never awaits, never
 *    branches on, and never throws from anything to do with recording.
 *
 * 2. EVERY CAPTURED CONTEXT IS ENCRYPTED. A model call carries the full prompt:
 *    system instructions, conversation history, retrieved documents, whatever
 *    the agent was given. That is the most sensitive material in the product,
 *    and it never touches the event log in the clear. It goes through the same
 *    sodium crypto_box_seal path as any other payload, or it is not captured at
 *    all. There is no plaintext branch to reach — `captureContext` requires a
 *    key at construction, so "encrypted" is a type-level property rather than
 *    a code path someone can forget.
 *
 * What lands in the EVENT (unencrypted, safe to read):
 *    provider, model, message/tool counts, token usage, stop reason, latency,
 *    a sha256 over the canonical request, and a payload_ref.
 * What lands in the encrypted BLOB:
 *    the full request context and the model's decision.
 */

import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createHash } from 'node:crypto';

import { argsDigest, type EventInput } from './schema.js';
import { sealPayload, type KeyFile } from './payloads.js';
import type { Recorder } from './recorder.js';

export const DEFAULT_TAP_PORT = 4180;

/** Providers we can read a request/response shape from. Anything else still proxies. */
export type Provider = 'anthropic' | 'openai' | 'unknown';

export interface TapOptions {
  /** Upstream base, e.g. https://api.anthropic.com */
  upstream: string;
  port?: number;
  /** Where events go. Absent means proxy-only, and it says so at startup. */
  recorder?: Recorder | null;
  /**
   * Payload key. REQUIRED to capture context: there is no unencrypted path.
   * Without it the tap still runs and still records model-call metadata, but
   * context and decision are not captured and the event says so.
   */
  payloadKey?: KeyFile | null;
  logDir?: string;
  /** Cap on captured context size. Beyond it, metadata only. */
  maxCaptureBytes?: number;
  log?: (line: string) => void;
}

export const DEFAULT_MAX_CAPTURE_BYTES = 2 * 1024 * 1024;

export function providerFor(path: string, upstream: string): Provider {
  if (/anthropic/i.test(upstream) || path.startsWith('/v1/messages')) return 'anthropic';
  if (/openai/i.test(upstream) || path.startsWith('/v1/chat/completions')) return 'openai';
  return 'unknown';
}

/** Is this path a model call worth recording, as opposed to a health ping? */
export function isModelCall(path: string): boolean {
  return /^\/v1\/(messages|chat\/completions|complete|responses)/.test(path);
}

export interface RequestFacts {
  model: string | null;
  messageCount: number | null;
  toolCount: number | null;
  stream: boolean;
  systemChars: number | null;
}

/** Read the safe, non-secret shape of a request body. Never returns content. */
export function readRequestFacts(body: string): RequestFacts {
  const empty: RequestFacts = { model: null, messageCount: null, toolCount: null, stream: false, systemChars: null };
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(body) as Record<string, unknown>;
  } catch {
    return empty;
  }
  const messages = Array.isArray(doc['messages']) ? doc['messages'] : null;
  const tools = Array.isArray(doc['tools']) ? doc['tools'] : null;
  const system = doc['system'];
  return {
    model: typeof doc['model'] === 'string' ? doc['model'] : null,
    messageCount: messages ? messages.length : null,
    toolCount: tools ? tools.length : null,
    stream: doc['stream'] === true,
    systemChars: typeof system === 'string' ? system.length : null,
  };
}

export interface DecisionFacts {
  stopReason: string | null;
  inputTokens: number | null;
  outputTokens: number | null;
  toolCalls: string[];
  textChars: number;
}

/** Reconstruct what the model decided, from a non-streaming JSON body. */
export function readDecisionJson(body: string, provider: Provider): DecisionFacts {
  const facts: DecisionFacts = { stopReason: null, inputTokens: null, outputTokens: null, toolCalls: [], textChars: 0 };
  let doc: Record<string, unknown>;
  try { doc = JSON.parse(body) as Record<string, unknown>; } catch { return facts; }

  if (provider === 'openai') {
    const choices = Array.isArray(doc['choices']) ? doc['choices'] : [];
    const first = choices[0] as Record<string, unknown> | undefined;
    facts.stopReason = typeof first?.['finish_reason'] === 'string' ? first['finish_reason'] : null;
    const msg = first?.['message'] as Record<string, unknown> | undefined;
    if (typeof msg?.['content'] === 'string') facts.textChars = (msg['content'] as string).length;
    for (const tc of (Array.isArray(msg?.['tool_calls']) ? msg['tool_calls'] : []) as Record<string, unknown>[]) {
      const fn = tc['function'] as Record<string, unknown> | undefined;
      if (typeof fn?.['name'] === 'string') facts.toolCalls.push(fn['name']);
    }
    const usage = doc['usage'] as Record<string, unknown> | undefined;
    facts.inputTokens = typeof usage?.['prompt_tokens'] === 'number' ? usage['prompt_tokens'] : null;
    facts.outputTokens = typeof usage?.['completion_tokens'] === 'number' ? usage['completion_tokens'] : null;
    return facts;
  }

  // Anthropic (and a sane default for anything message-shaped).
  facts.stopReason = typeof doc['stop_reason'] === 'string' ? doc['stop_reason'] : null;
  for (const block of (Array.isArray(doc['content']) ? doc['content'] : []) as Record<string, unknown>[]) {
    if (block['type'] === 'text' && typeof block['text'] === 'string') facts.textChars += (block['text'] as string).length;
    if (block['type'] === 'tool_use' && typeof block['name'] === 'string') facts.toolCalls.push(block['name'] as string);
  }
  const usage = doc['usage'] as Record<string, unknown> | undefined;
  facts.inputTokens = typeof usage?.['input_tokens'] === 'number' ? usage['input_tokens'] : null;
  facts.outputTokens = typeof usage?.['output_tokens'] === 'number' ? usage['output_tokens'] : null;
  return facts;
}

/** Reconstruct the decision from an SSE stream body. */
export function readDecisionStream(raw: string, provider: Provider): DecisionFacts {
  const facts: DecisionFacts = { stopReason: null, inputTokens: null, outputTokens: null, toolCalls: [], textChars: 0 };
  for (const line of raw.split('\n')) {
    if (!line.startsWith('data:')) continue;
    const payload = line.slice(5).trim();
    if (payload === '' || payload === '[DONE]') continue;
    let ev: Record<string, unknown>;
    try { ev = JSON.parse(payload) as Record<string, unknown>; } catch { continue; }

    if (provider === 'openai') {
      const choice = (Array.isArray(ev['choices']) ? ev['choices'] : [])[0] as Record<string, unknown> | undefined;
      const delta = choice?.['delta'] as Record<string, unknown> | undefined;
      if (typeof delta?.['content'] === 'string') facts.textChars += (delta['content'] as string).length;
      if (typeof choice?.['finish_reason'] === 'string') facts.stopReason = choice['finish_reason'] as string;
      continue;
    }

    const type = ev['type'];
    if (type === 'content_block_delta') {
      const delta = ev['delta'] as Record<string, unknown> | undefined;
      if (typeof delta?.['text'] === 'string') facts.textChars += (delta['text'] as string).length;
    } else if (type === 'content_block_start') {
      const block = ev['content_block'] as Record<string, unknown> | undefined;
      if (block?.['type'] === 'tool_use' && typeof block['name'] === 'string') facts.toolCalls.push(block['name'] as string);
    } else if (type === 'message_delta') {
      const delta = ev['delta'] as Record<string, unknown> | undefined;
      if (typeof delta?.['stop_reason'] === 'string') facts.stopReason = delta['stop_reason'] as string;
      const usage = ev['usage'] as Record<string, unknown> | undefined;
      if (typeof usage?.['output_tokens'] === 'number') facts.outputTokens = usage['output_tokens'];
    } else if (type === 'message_start') {
      const msg = ev['message'] as Record<string, unknown> | undefined;
      const usage = msg?.['usage'] as Record<string, unknown> | undefined;
      if (typeof usage?.['input_tokens'] === 'number') facts.inputTokens = usage['input_tokens'];
    }
  }
  return facts;
}

/**
 * The encrypted context blob.
 *
 * Exists as its own type so it is obvious at a glance that this object — and
 * only this object — carries prompt material, and that its single consumer is
 * sealPayload().
 */
export interface CapturedContext {
  v: 1;
  provider: Provider;
  path: string;
  request: unknown;
  response: unknown;
  streamed: boolean;
}

export interface TapHandle {
  port: number;
  close: () => Promise<void>;
  /** Model calls recorded since start. */
  recorded: () => number;
}

export function startTap(opts: TapOptions): Promise<TapHandle> {
  const upstream = new URL(opts.upstream);
  const isTls = upstream.protocol === 'https:';
  const doRequest = isTls ? httpsRequest : httpRequest;
  const maxCapture = opts.maxCaptureBytes ?? DEFAULT_MAX_CAPTURE_BYTES;
  const log = opts.log ?? ((l) => process.stderr.write(`${l}\n`));
  let recorded = 0;

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const startedAt = Date.now();
    const path = req.url ?? '/';
    const provider = providerFor(path, opts.upstream);
    const capture = isModelCall(path);

    const reqChunks: Buffer[] = [];
    let reqBytes = 0;

    req.on('data', (c: Buffer) => {
      // Buffering only what we might capture; the forward is unaffected either way.
      reqBytes += c.length;
      if (capture && reqBytes <= maxCapture) reqChunks.push(c);
    });

    const headers = { ...req.headers };
    delete headers['host'];
    delete headers['content-length'];

    const upstreamReq = doRequest(
      {
        protocol: upstream.protocol,
        hostname: upstream.hostname,
        port: upstream.port || (isTls ? 443 : 80),
        method: req.method,
        path,
        headers: { ...headers, host: upstream.host },
      },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);

        const resChunks: Buffer[] = [];
        let resBytes = 0;

        upstreamRes.on('data', (c: Buffer) => {
          // FORWARD FIRST, ALWAYS. Nothing below this line may delay the agent.
          res.write(c);
          resBytes += c.length;
          if (capture && resBytes <= maxCapture) resChunks.push(c);
        });

        upstreamRes.on('end', () => {
          res.end();
          if (!capture) return;
          // Recording happens after the response is closed out, so its cost is
          // off the critical path entirely.
          setImmediate(() => {
            try {
              recordModelCall({
                opts, provider, path, startedAt, log,
                statusCode: upstreamRes.statusCode ?? 0,
                requestBody: Buffer.concat(reqChunks).toString('utf8'),
                responseBody: Buffer.concat(resChunks).toString('utf8'),
                truncated: reqBytes > maxCapture || resBytes > maxCapture,
                contentType: String(upstreamRes.headers['content-type'] ?? ''),
              });
              recorded++;
            } catch (e) {
              log(`[orisan-tap] capture failed, request unaffected: ${(e as Error).message}`);
            }
          });
        });
      },
    );

    upstreamReq.on('error', (e) => {
      // An upstream failure is the agent's problem to see, not ours to swallow.
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { type: 'orisan_tap_upstream_error', message: e.message } }));
    });

    req.pipe(upstreamReq);
  });

  const port = opts.port ?? DEFAULT_TAP_PORT;
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        port: typeof addr === 'object' && addr !== null ? addr.port : port,
        close: () => new Promise<void>((d) => { server.close(() => d()); }),
        recorded: () => recorded,
      });
    });
  });
}

interface RecordArgs {
  opts: TapOptions;
  provider: Provider;
  path: string;
  startedAt: number;
  statusCode: number;
  requestBody: string;
  responseBody: string;
  truncated: boolean;
  contentType: string;
  log: (line: string) => void;
}

function recordModelCall(a: RecordArgs): void {
  const { opts, provider, path, startedAt } = a;
  if (!opts.recorder) return;

  const streamed = a.contentType.includes('event-stream');
  const facts = readRequestFacts(a.requestBody);
  const decision = streamed
    ? readDecisionStream(a.responseBody, provider)
    : readDecisionJson(a.responseBody, provider);

  // The context blob is the only thing carrying prompt material, and it only
  // ever leaves this function through sealPayload.
  let payloadRef: string | null = null;
  let captureNote = '';
  if (a.truncated) {
    captureNote = ' (context not captured: over the size cap)';
  } else if (!opts.payloadKey || !opts.logDir) {
    // No key means no encryption means no capture. There is deliberately no
    // fallback that writes this in the clear.
    captureNote = ' (context not captured: no payload key configured)';
  } else {
    try {
      const context: CapturedContext = {
        v: 1, provider, path, streamed,
        request: safeParse(a.requestBody),
        response: streamed ? a.responseBody : safeParse(a.responseBody),
      };
      payloadRef = sealPayload(opts.logDir, opts.payloadKey, JSON.stringify(context));
    } catch (e) {
      // Sealing failed: record the call without context rather than losing the
      // event, and never in the clear.
      captureNote = ' (context not captured: sealing failed)';
      a.log(`[orisan-tap] sealing failed, recording metadata only: ${(e as Error).message}`);
    }
  }

  const outcome = a.statusCode >= 400
    ? `error: HTTP ${a.statusCode}`
    : `${decision.stopReason ?? 'ok'}${decision.toolCalls.length ? ` -> ${decision.toolCalls.join(', ')}` : ''}${captureNote}`;

  const input: EventInput = {
    actor: {
      human: process.env['USER'] ?? null,
      agent_id: `spiffe://orisan/model/${provider}`,
      tool: facts.model ?? provider,
    },
    kind: 'model_call',
    target: facts.model ?? path,
    // A digest over the canonical request, so two identical prompts are
    // comparable without either being readable.
    args_digest: argsDigest({
      provider, model: facts.model, messages: facts.messageCount,
      tools: facts.toolCount, systemChars: facts.systemChars,
      requestHash: createHash('sha256').update(a.requestBody).digest('hex'),
    }),
    payload_ref: payloadRef,
    outcome,
    duration_ms: Date.now() - startedAt,
  };

  void opts.recorder.record(input).catch((e: unknown) => {
    a.log(`[orisan-tap] event dropped: ${(e as Error).message}`);
  });
}

function safeParse(s: string): unknown {
  try { return JSON.parse(s) as unknown; } catch { return s; }
}
