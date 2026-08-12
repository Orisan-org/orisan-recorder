/**
 * R2.3 — the local UI server.
 *
 * Binds to 127.0.0.1 only and has no authentication. That is a deliberate
 * trade for a single-user local tool, and it is only safe because of the
 * binding: the loopback interface is the access control. Two consequences are
 * enforced here rather than left to a README — the listener never binds a
 * routable address, and every request is checked for a loopback Host header so
 * a DNS-rebinding page in the user's browser cannot drive the API.
 *
 * The API is read-only over the store. The two exceptions are attach and
 * detach, which are the whole point of the Agents screen; both are explicit
 * user actions behind a POST.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { existsSync, readFileSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';

import { attach, detach, discardBackup, isAttached } from './attach.js';
import { bannerFor } from './banner.js';
import { buildEvidenceBundle } from './bundle.js';
import { scan } from './discover.js';
import { EventStore } from './store.js';
import { verify } from './verify.js';
import { readCheckpoints } from './checkpoint.js';

export const DEFAULT_PORT = 4173;

export interface ServerOptions {
  logDir: string;
  port?: number;
  uiDir?: string;
  shimPath: string;
  /** Interpreter for the shim. Defaults to this process's node. */
  nodePath?: string;
  signingKeyPath?: string;
  witnessFile?: string;
  tsaCaFile?: string;
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
};

function json(res: ServerResponse, status: number, body: unknown): void {
  const data = Buffer.from(`${JSON.stringify(body)}\n`, 'utf8');
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': data.length });
  res.end(data);
}

/** Only loopback Hosts. Defeats DNS rebinding against a no-auth local API. */
export function hostIsLoopback(host: string | undefined): boolean {
  if (!host) return false;
  const name = host.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase();
  return name === 'localhost' || name === '127.0.0.1' || name === '::1';
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  if (chunks.length === 0) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown; } catch { return {}; }
}

function verifyNow(opts: ServerOptions) {
  return verify(opts.logDir, {
    ...(opts.tsaCaFile !== undefined ? { tsaCaFile: opts.tsaCaFile } : {}),
    ...(opts.witnessFile !== undefined ? { witnessFile: opts.witnessFile } : {}),
  });
}

/** Sessions, derived from the event log: a session is a run of events. */
function sessions(logDir: string): { id: string; startedAt: string; endedAt: string; events: number; flagged: number }[] {
  if (!existsSync(logDir)) return [];
  const events = EventStore.open(logDir, { readOnly: true }).store.readAll();
  if (events.length === 0) return [];
  // R1 has no session id on events; the whole log is one session for now, and
  // saying so is better than inventing boundaries the data does not carry.
  return [{
    id: 'current',
    startedAt: events[0]!.ts,
    endedAt: events[events.length - 1]!.ts,
    events: events.length,
    flagged: events.filter((e) => e.kind === 'flag').length,
  }];
}

export function createApp(opts: ServerOptions) {
  const uiDir = opts.uiDir ?? join(process.cwd(), 'ui', 'dist');

  return createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const path = url.pathname;

      if (!hostIsLoopback(req.headers.host)) {
        json(res, 403, { error: 'this server only answers loopback requests' });
        return;
      }

      try {
        if (path === '/api/scan') { json(res, 200, scan()); return; }

        if (path === '/api/status') {
          const report = verifyNow(opts);
          json(res, 200, {
            logDir: opts.logDir,
            banner: bannerFor({ exitCode: report.exitCode, findings: report.findings }),
            exitCode: report.exitCode,
            events: report.events,
            checkpoints: report.checkpoints,
            anchored: report.anchored,
            witnessConfigured: opts.witnessFile !== undefined,
          });
          return;
        }

        if (path === '/api/sessions') { json(res, 200, { sessions: sessions(opts.logDir) }); return; }

        if (path === '/api/events') {
          const events = existsSync(opts.logDir)
            ? EventStore.open(opts.logDir, { readOnly: true }).store.readAll()
            : [];
          json(res, 200, {
            events: events.map((e) => ({
              seq: e.seq, ts: e.ts, kind: e.kind, target: e.target,
              outcome: e.outcome, duration_ms: e.duration_ms,
              actor: e.actor, args_digest: e.args_digest,
            })),
            checkpoints: readCheckpoints(opts.logDir).length,
          });
          return;
        }

        if (path === '/api/attach' && req.method === 'POST') {
          const body = (await readBody(req)) as { config?: string };
          if (!body.config) { json(res, 400, { error: 'config path required' }); return; }
          const r = attach(body.config, {
            logDir: opts.logDir,
            shimPath: opts.shimPath,
            ...(opts.nodePath !== undefined ? { nodePath: opts.nodePath } : {}),
            ...(opts.signingKeyPath !== undefined ? { signingKeyPath: opts.signingKeyPath } : {}),
            ...(opts.witnessFile !== undefined ? { witnessFile: opts.witnessFile } : {}),
          });
          json(res, 200, { ...r, note: 'restart the client for this to take effect' });
          return;
        }

        if (path === '/api/detach' && req.method === 'POST') {
          const body = (await readBody(req)) as { config?: string };
          if (!body.config) { json(res, 400, { error: 'config path required' }); return; }
          const r = detach(body.config);
          discardBackup(body.config);
          json(res, 200, r);
          return;
        }

        if (path === '/api/attached') {
          const cfg = url.searchParams.get('config');
          json(res, 200, { attached: cfg ? isAttached(cfg) : false });
          return;
        }

        if (path === '/api/export') {
          const zip = buildEvidenceBundle(opts.logDir, { report: verifyNow(opts) });
          res.writeHead(200, {
            'content-type': 'application/zip',
            'content-length': zip.length,
            'content-disposition': 'attachment; filename="orisan-evidence.zip"',
          });
          res.end(zip);
          return;
        }

        // ---- static UI -------------------------------------------------------
        const rel = path === '/' ? 'index.html' : normalize(path).replace(/^(\.\.[/\\])+/, '').replace(/^\//, '');
        const file = join(uiDir, rel);
        if (existsSync(file) && file.startsWith(uiDir)) {
          const data = readFileSync(file);
          res.writeHead(200, { 'content-type': MIME[extname(file)] ?? 'application/octet-stream' });
          res.end(data);
          return;
        }
        // SPA fallback.
        const index = join(uiDir, 'index.html');
        if (existsSync(index)) {
          res.writeHead(200, { 'content-type': MIME['.html']! });
          res.end(readFileSync(index));
          return;
        }
        json(res, 404, { error: 'not found; run `npm run build:ui`' });
      } catch (e) {
        json(res, 500, { error: (e as Error).message });
      }
    })();
  });
}

export function startServer(opts: ServerOptions): Promise<{ port: number; close: () => Promise<void> }> {
  const server = createApp(opts);
  const requested = opts.port ?? DEFAULT_PORT;
  return new Promise((resolve) => {
    // 127.0.0.1 explicitly: never a routable interface.
    server.listen(requested, '127.0.0.1', () => {
      // Report the port actually bound, not the one asked for — port 0 means
      // "pick one", and tests rely on being told which.
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : requested;
      resolve({
        port,
        close: () => new Promise<void>((done) => { server.close(() => done()); }),
      });
    });
  });
}
