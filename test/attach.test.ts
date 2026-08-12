/** R2.2 — attach/detach and the passthrough shim. */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { attach, backupPathFor, detach, discardBackup, isAttached, SHIM_MARKER } from '../src/attach.js';
import { outcomeOf, takeLines, toolCallOf } from '../src/shim.js';
import { EventStore } from '../src/store.js';

let home: string;
let logDir: string;
let keyDir: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'orisan-att-'));
  logDir = mkdtempSync(join(tmpdir(), 'orisan-attlog-'));
  keyDir = mkdtempSync(join(tmpdir(), 'orisan-attkey-'));
});
afterEach(() => {
  for (const d of [home, logDir, keyDir]) rmSync(d, { recursive: true, force: true });
});

const SHIM = join(process.cwd(), 'src', 'shim-main.ts');
const TSX = join(process.cwd(), 'node_modules', '.bin', 'tsx');
const FAKE = join(process.cwd(), 'test', 'fixtures', 'fake-mcp-server.mjs');

/** A config written with idiosyncratic formatting we must restore exactly. */
const ORIGINAL_TEXT = `{
    "mcpServers": {
        "fake": { "command": "node", "args": ["${FAKE}"] },
        "remote": { "url": "https://mcp.example.invalid/sse" }
    },
    "otherSetting":   true
}
`;

function writeConfig(): string {
  const p = join(home, 'Library/Application Support/Claude/claude_desktop_config.json');
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, ORIGINAL_TEXT);
  return p;
}

const opts = () => ({ logDir, shimPath: SHIM, nodePath: TSX, signingKeyPath: join(keyDir, 'signing.key') });

describe('attach', () => {
  it('writes the backup before touching the original', () => {
    const cfg = writeConfig();
    const r = attach(cfg, opts());
    expect(existsSync(r.backupPath)).toBe(true);
    expect(readFileSync(r.backupPath, 'utf8')).toBe(ORIGINAL_TEXT);
  });

  it('routes stdio servers through the shim and marks them', () => {
    const cfg = writeConfig();
    const r = attach(cfg, opts());
    expect(r.rewritten).toEqual(['fake']);
    const doc = JSON.parse(readFileSync(cfg, 'utf8')) as any;
    const fake = doc.mcpServers.fake;
    expect(fake.args).toContain(SHIM);
    expect(fake.args).toContain('--');
    expect(fake[SHIM_MARKER].original).toEqual({ command: 'node', args: [FAKE] });
  });

  it('skips url-only servers, which have no stdio to sit in front of', () => {
    const cfg = writeConfig();
    expect(attach(cfg, opts()).skipped).toEqual(['remote']);
  });

  it('refuses to attach twice, which would nest shims', () => {
    const cfg = writeConfig();
    attach(cfg, opts());
    expect(() => attach(cfg, opts())).toThrow(/already attached/);
  });

  it('refuses to clobber an existing backup', () => {
    const cfg = writeConfig();
    writeFileSync(backupPathFor(cfg), 'someone elses backup');
    expect(() => attach(cfg, opts())).toThrow(/refusing to overwrite/);
    // And the original is untouched.
    expect(readFileSync(cfg, 'utf8')).toBe(ORIGINAL_TEXT);
  });

  it('refuses a config with no mcpServers block', () => {
    const p = join(home, 'x.json');
    writeFileSync(p, '{"nope":1}');
    expect(() => attach(p, opts())).toThrow(/no mcpServers block/);
    expect(existsSync(backupPathFor(p))).toBe(false);
  });
});

describe('detach', () => {
  it('ACCEPTANCE: restores the byte-identical original', () => {
    const cfg = writeConfig();
    const before = readFileSync(cfg);
    attach(cfg, opts());
    expect(readFileSync(cfg).equals(before)).toBe(false); // it really did change

    const r = detach(cfg);
    expect(r.byteIdentical).toBe(true);
    expect(readFileSync(cfg).equals(before)).toBe(true);
    expect(readFileSync(cfg, 'utf8')).toBe(ORIGINAL_TEXT);
    expect(isAttached(cfg)).toBe(false);
  });

  it('leaves the backup in place until explicitly discarded', () => {
    const cfg = writeConfig();
    attach(cfg, opts());
    detach(cfg);
    expect(existsSync(backupPathFor(cfg))).toBe(true);
    discardBackup(cfg);
    expect(existsSync(backupPathFor(cfg))).toBe(false);
  });

  it('refuses when there is no backup', () => {
    const cfg = writeConfig();
    expect(() => detach(cfg)).toThrow(/no backup to restore/);
  });
});

describe('shim message parsing', () => {
  it('recognises a tools/call request', () => {
    const c = toolCallOf({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'read', arguments: { a: 1 } } });
    expect(c).toEqual({ id: '7', name: 'read', args: { a: 1 } });
  });

  it('ignores other methods and notifications', () => {
    expect(toolCallOf({ method: 'initialize', id: 1 })).toBeNull();
    expect(toolCallOf({ method: 'tools/call', params: { name: 'x' } })).toBeNull(); // no id
  });

  it('classifies results, tool errors and protocol errors', () => {
    expect(outcomeOf({ id: 1, result: { content: [] } })).toEqual({ id: '1', outcome: 'ok' });
    expect(outcomeOf({ id: 2, result: { isError: true } })!.outcome).toMatch(/isError/);
    expect(outcomeOf({ id: 3, error: { message: 'boom' } })!.outcome).toBe('error: boom');
  });

  it('only yields complete lines, keeping the partial tail', () => {
    expect(takeLines('{"a":1}\n{"b":2}\n{"c"')).toEqual({ lines: ['{"a":1}', '{"b":2}'], rest: '{"c"' });
    expect(takeLines('no newline yet')).toEqual({ lines: [], rest: 'no newline yet' });
  });
});

describe('ACCEPTANCE: a round-trip through the shim produces events', () => {
  /** Drive the shim like an MCP client would. */
  function roundTrip(extraEnv: Record<string, string> = {}): Promise<string> {
    return new Promise((resolve, reject) => {
      const child = spawn(TSX, [
        SHIM, '--log', logDir, '--name', 'fake',
        '--key', join(keyDir, 'signing.key'),
        '--', 'node', FAKE,
      ], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, ...extraEnv } });

      let out = '';
      child.stdout.on('data', (d: Buffer) => { out += d.toString(); });
      child.on('error', reject);
      child.on('close', () => resolve(out));

      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' })}\n`);
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'read_file', arguments: { path: '/tmp/fake' } } })}\n`);
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'explode', arguments: {} } })}\n`);
      setTimeout(() => {
        child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'shutdown' })}\n`);
        child.stdin.end();
      }, 900);
    });
  }

  it('forwards responses untouched and records both calls', async () => {
    const out = await roundTrip();
    // Passthrough: the client sees the server's real answers.
    expect(out).toMatch(/"protocolVersion":"2024-11-05"/);
    expect(out).toMatch(/fake result for read_file/);

    const events = EventStore.open(logDir, { readOnly: true }).store.readAll();
    const calls = events.filter((e) => e.kind === 'tool_call');
    expect(calls.map((e) => e.target).sort()).toEqual(['explode', 'read_file']);

    const ok = calls.find((e) => e.target === 'read_file')!;
    expect(ok.outcome).toBe('ok');
    expect(ok.args_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(ok.duration_ms).toBeGreaterThanOrEqual(0);
    expect(ok.actor.tool).toBe('fake');

    expect(calls.find((e) => e.target === 'explode')!.outcome).toMatch(/error/);
  }, 20_000);

  it('the agent still works when recording cannot write', async () => {
    // Point the log at a path that cannot be created.
    const broken = '/dev/null/cannot-exist';
    const out = await new Promise<string>((resolve, reject) => {
      const child = spawn(TSX, [SHIM, '--log', broken, '--name', 'fake', '--', 'node', FAKE],
        { stdio: ['pipe', 'pipe', 'pipe'] });
      let o = '';
      child.stdout.on('data', (d: Buffer) => { o += d.toString(); });
      child.on('error', reject);
      child.on('close', () => resolve(o));
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: {} } })}\n`);
      setTimeout(() => child.stdin.end(), 700);
    });
    // Recording is dead; the tool call still succeeded.
    expect(out).toMatch(/fake result for read_file/);
  }, 20_000);
});
