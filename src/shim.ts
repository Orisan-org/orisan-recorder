#!/usr/bin/env node
/**
 * R2.2 — stdio passthrough shim.
 *
 * Sits between an MCP client and an MCP server. Bytes go through untouched in
 * both directions; tool calls are recorded as a side effect.
 *
 * THE RULE THIS FILE EXISTS TO OBEY: recording must never break the user's
 * workflow. Every recording path is wrapped, every failure is swallowed to
 * stderr, and nothing about the child's stdin/stdout is conditional on the
 * recorder working. If the log directory is read-only, the disk is full, or
 * this file has a bug, the agent still talks to its server.
 *
 * That is the opposite of the trade-off the recorder core makes, where a
 * failed append is fatal. Here the user's tool is the priority; there the
 * evidence is. Both are deliberate and they point in opposite directions.
 *
 * Framing: MCP over stdio is newline-delimited JSON-RPC. We split on newlines,
 * try to parse each line, and forward regardless — a line we cannot parse is
 * still passed through byte-for-byte.
 */

import { spawn } from 'node:child_process';

import { Recorder } from './recorder.js';
import { argsDigest, type EventInput } from './schema.js';

interface PendingCall {
  toolName: string;
  argsDigest: string | null;
  startedAt: number;
}

export interface ShimConfig {
  logDir: string;
  serverName: string;
  command: string;
  args: string[];
  signingKeyPath?: string;
  witnessFile?: string;
}

/** Extract a tool name from an MCP tools/call request, if that is what it is. */
export function toolCallOf(msg: unknown): { id: string; name: string; args: unknown } | null {
  if (!msg || typeof msg !== 'object') return null;
  const m = msg as Record<string, unknown>;
  if (m['method'] !== 'tools/call') return null;
  const params = m['params'];
  if (!params || typeof params !== 'object') return null;
  const p = params as Record<string, unknown>;
  if (typeof p['name'] !== 'string') return null;
  const id = m['id'];
  if (typeof id !== 'string' && typeof id !== 'number') return null;
  return { id: String(id), name: p['name'], args: p['arguments'] ?? null };
}

/** Classify a JSON-RPC response as ok or error. */
export function outcomeOf(msg: unknown): { id: string; outcome: string } | null {
  if (!msg || typeof msg !== 'object') return null;
  const m = msg as Record<string, unknown>;
  const id = m['id'];
  if (typeof id !== 'string' && typeof id !== 'number') return null;
  if ('error' in m) {
    const err = m['error'] as Record<string, unknown> | undefined;
    const message = err && typeof err['message'] === 'string' ? err['message'] : 'error';
    return { id: String(id), outcome: `error: ${message}` };
  }
  if ('result' in m) {
    const res = m['result'] as Record<string, unknown> | undefined;
    // MCP marks tool-level failures with isError on the result.
    if (res && res['isError'] === true) return { id: String(id), outcome: 'error: tool reported isError' };
    return { id: String(id), outcome: 'ok' };
  }
  return null;
}

/**
 * Split a growing buffer into complete lines.
 * Returns the lines and whatever partial tail remains.
 */
export function takeLines(buffer: string): { lines: string[]; rest: string } {
  const idx = buffer.lastIndexOf('\n');
  if (idx === -1) return { lines: [], rest: buffer };
  const complete = buffer.slice(0, idx);
  return { lines: complete.split('\n').filter((l) => l.length > 0), rest: buffer.slice(idx + 1) };
}

export async function runShim(cfg: ShimConfig): Promise<number> {
  const pending = new Map<string, PendingCall>();

  // A recorder that fails to open must not stop the server from starting.
  let recorder: Recorder | null = null;
  try {
    recorder = Recorder.open(cfg.logDir, {
      ...(cfg.signingKeyPath !== undefined ? { signingKeyPath: cfg.signingKeyPath } : {}),
      ...(cfg.witnessFile !== undefined ? { witnessFile: cfg.witnessFile } : {}),
    });
  } catch (e) {
    process.stderr.write(`[orisan] recording disabled: ${(e as Error).message}\n`);
  }

  const record = (input: EventInput): void => {
    if (!recorder) return;
    // Fire and forget. An await here would put the recorder on the critical
    // path of the user's tool call, which is exactly what must not happen.
    void recorder.record(input).catch((e: unknown) => {
      process.stderr.write(`[orisan] event dropped: ${(e as Error).message}\n`);
    });
  };

  const child = spawn(cfg.command, cfg.args, { stdio: ['pipe', 'pipe', 'inherit'] });

  child.on('error', (e) => {
    process.stderr.write(`[orisan] could not start ${cfg.command}: ${e.message}\n`);
    process.exitCode = 127;
  });

  // ---- client -> server ----------------------------------------------------
  let inBuf = '';
  process.stdin.on('data', (chunk: Buffer) => {
    child.stdin.write(chunk); // forward FIRST, always
    try {
      inBuf += chunk.toString('utf8');
      const { lines, rest } = takeLines(inBuf);
      inBuf = rest;
      for (const line of lines) {
        let msg: unknown;
        try { msg = JSON.parse(line); } catch { continue; }
        const call = toolCallOf(msg);
        if (!call) continue;
        pending.set(call.id, {
          toolName: call.name,
          argsDigest: call.args === null ? null : argsDigest(call.args),
          startedAt: Date.now(),
        });
      }
    } catch (e) {
      process.stderr.write(`[orisan] inbound parse failed: ${(e as Error).message}\n`);
    }
  });
  process.stdin.on('end', () => child.stdin.end());

  // ---- server -> client ----------------------------------------------------
  let outBuf = '';
  child.stdout.on('data', (chunk: Buffer) => {
    process.stdout.write(chunk); // forward FIRST, always
    try {
      outBuf += chunk.toString('utf8');
      const { lines, rest } = takeLines(outBuf);
      outBuf = rest;
      for (const line of lines) {
        let msg: unknown;
        try { msg = JSON.parse(line); } catch { continue; }
        const res = outcomeOf(msg);
        if (!res) continue;
        const call = pending.get(res.id);
        if (!call) continue;
        pending.delete(res.id);
        record({
          actor: {
            human: process.env['USER'] ?? null,
            agent_id: `spiffe://orisan/mcp/${cfg.serverName}`,
            tool: cfg.serverName,
          },
          kind: 'tool_call',
          target: call.toolName,
          args_digest: call.argsDigest,
          payload_ref: null,
          outcome: res.outcome,
          duration_ms: Date.now() - call.startedAt,
        });
      }
    } catch (e) {
      process.stderr.write(`[orisan] outbound parse failed: ${(e as Error).message}\n`);
    }
  });

  return await new Promise<number>((resolve) => {
    child.on('close', (code) => {
      try {
        // Seal the session, but never hang the exit on it.
        void recorder?.end().catch(() => undefined);
      } catch { /* recording must not affect exit */ }
      resolve(code ?? 0);
    });
  });
}
