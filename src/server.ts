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
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

import { attach, detach, discardBackup, isAttached } from './attach.js';
import { bannerFor } from './banner.js';
import { GLOSSARY, SCREENS } from './explain.js';
import { prove } from './prove.js';
import { defaultHome, setupSteps } from './quickstart.js';
import { loadKeyFile, openPayload } from './payloads.js';
import { buildEvidenceBundle } from './bundle.js';
import { scan } from './discover.js';
import { EventIndex } from './index-db.js';
import { EventStore, peekHeadSeq } from './store.js';
import { verify, type VerifyReport } from './verify.js';
import { fetchHead, readWitnessConfig, type WitnessConfig } from './witness-service.js';
import { readCheckpoints } from './checkpoint.js';

export const DEFAULT_PORT = 4173;

/**
 * Where the built interface lives, resolved from THIS module rather than the
 * working directory.
 *
 * process.cwd() works when you run from the repo and fails the moment the
 * package is installed and launched from somewhere else — which is every real
 * install. Checks the packaged layout first, then the repo layout.
 */
export function defaultUiDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, '..', 'ui', 'dist'),   // installed: dist/server.js -> ../ui/dist
    join(here, '..', '..', 'ui', 'dist'),
    join(process.cwd(), 'ui', 'dist'),
  ];
  return candidates.find((c) => existsSync(join(c, 'index.html'))) ?? candidates[0]!;
}

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
  /** Payload key, so the UI can show what the agent actually saw. */
  payloadKeyPath?: string;
  /** Root of the Orisan home, so the UI can show the same setup steps the CLI printed. */
  orisanHome?: string;
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

/**
 * Verify, including asking the witness what it remembers.
 *
 * This has to be async because the head is fetched over the network, and the
 * first version of it was not: the server called verify() directly and never
 * read witness.json, so the interface reported "no witness" on a log that had
 * one registered — the banner could never have gone green no matter how the
 * witness was deployed. Only running it end to end showed that.
 */
async function verifyNow(opts: ServerOptions): Promise<VerifyReport> {
  const base = {
    ...(opts.tsaCaFile !== undefined ? { tsaCaFile: opts.tsaCaFile } : {}),
    ...(opts.witnessFile !== undefined ? { witnessFile: opts.witnessFile } : {}),
  };

  let cfg: WitnessConfig | null = null;
  try { cfg = readWitnessConfig(opts.logDir); } catch { cfg = null; }
  if (!cfg) return verify(opts.logDir, base);

  const fetched = await fetchHead(cfg);
  return verify(opts.logDir, {
    ...base,
    witnessService: {
      logId: cfg.log_id,
      url: cfg.url,
      reachable: fetched.reachable,
      ...(fetched.error !== undefined ? { error: fetched.error } : {}),
      ...(fetched.head !== undefined ? { head: fetched.head } : {}),
      ...(fetched.signatureValid !== undefined ? { signatureValid: fetched.signatureValid } : {}),
    },
  });
}

/**
 * The index, brought up to date only if it has fallen behind.
 *
 * Staleness is a single integer comparison against the tail of the log, so the
 * common case costs nothing. Before this, every /api/sessions and /api/events
 * call read the entire event log to group it — fine for a demo, quadratic-ish
 * misery for a long-running recorder, and about to get hotter.
 */
function freshIndex(logDir: string): EventIndex | null {
  if (!existsSync(logDir)) return null;
  const index = EventIndex.open(logDir);
  if (index.maxSeq() !== peekHeadSeq(logDir)) {
    index.rebuild(EventStore.open(logDir, { readOnly: true }).store);
  }
  return index;
}

export interface SessionSummary {
  id: string;
  startedAt: string;
  endedAt: string;
  events: number;
  flagged: number;
  agents: string[];
  firstSeq: number;
  lastSeq: number;
}

/**
 * Sessions, grouped from the events themselves.
 *
 * Until v3 this fabricated a single session called "current" because events
 * carried no session id — an invented boundary, and one that quietly implied a
 * whole log was one run. Now the grouping comes from a field that is inside
 * each event's hash, so it cannot be edited after the fact.
 */
function sessions(index: EventIndex | null): SessionSummary[] {
  if (!index) return [];
  return index.sessions().map((r) => ({
    id: r.session_id,
    startedAt: r.started_at,
    endedAt: r.ended_at,
    events: r.events,
    flagged: r.flagged,
    agents: (r.agents ?? '').split(',').filter((a) => a.length > 0),
    firstSeq: r.first_seq,
    lastSeq: r.last_seq,
  }));
}

export function createApp(opts: ServerOptions) {
  const uiDir = opts.uiDir ?? defaultUiDir();

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
          const report = await verifyNow(opts);
          json(res, 200, {
            logDir: opts.logDir,
            banner: bannerFor({ exitCode: report.exitCode, findings: report.findings }),
            exitCode: report.exitCode,
            events: report.events,
            checkpoints: report.checkpoints,
            anchored: report.anchored,
            // A registered witness SERVICE counts, not just the local witness
            // file. This reported false against a green banner that credited
            // the witness by name — the Evidence screen then said "no witness
            // configured" on a log that had one.
            witnessConfigured:
              opts.witnessFile !== undefined || readWitnessConfig(opts.logDir) !== null,
          });
          return;
        }

        if (path === '/api/setup') {
          // Same words as the terminal: "why isn't this green?" must not have
          // two different answers depending on where you ask.
          const home = defaultHome(opts.orisanHome);
          json(res, 200, { steps: setupSteps({ ...home, logDir: opts.logDir }) });
          return;
        }

        if (path === '/api/explain') {
          json(res, 200, { screens: SCREENS, glossary: GLOSSARY });
          return;
        }

        // One event, expanded: what the agent saw, decided, and received.
        const detail = /^\/api\/events\/(\d+)$/.exec(path);
        if (detail) {
          const seq = Number.parseInt(detail[1]!, 10);
          const event = existsSync(opts.logDir)
            ? EventStore.open(opts.logDir, { readOnly: true }).store.readAll().find((e) => e.seq === seq)
            : undefined;
          if (!event) { json(res, 404, { error: `no event ${seq}` }); return; }

          // Context is encrypted at rest. It is only decrypted here, on an
          // explicit request, and only if the operator supplied the key.
          let context: unknown = null;
          let contextState = 'none';
          if (event.payload_ref === null) {
            contextState = 'not_captured';
          } else if (!opts.payloadKeyPath || !existsSync(opts.payloadKeyPath)) {
            contextState = 'locked';
          } else {
            try {
              context = JSON.parse(
                openPayload(opts.logDir, loadKeyFile(opts.payloadKeyPath), event.payload_ref).toString('utf8'),
              ) as unknown;
              contextState = 'unlocked';
            } catch (e) {
              contextState = 'unreadable';
              context = { error: (e as Error).message };
            }
          }

          json(res, 200, {
            event: {
              seq: event.seq, session_id: event.session_id, ts: event.ts, kind: event.kind,
              target: event.target, outcome: event.outcome, duration_ms: event.duration_ms,
              actor: event.actor, args_digest: event.args_digest, payload_ref: event.payload_ref,
              hash: event.hash, prev_hash: event.prev_hash,
            },
            contextState,
            context,
          });
          return;
        }

        if (path === '/api/prove' && req.method === 'POST') {
          json(res, 200, prove(opts.logDir, {
            ...(opts.tsaCaFile !== undefined ? { tsaCaFile: opts.tsaCaFile } : {}),
            ...(opts.witnessFile !== undefined ? { witnessFile: opts.witnessFile } : {}),
          }));
          return;
        }

        if (path === '/api/sessions') {
          const index = freshIndex(opts.logDir);
          try { json(res, 200, { sessions: sessions(index) }); } finally { index?.close(); }
          return;
        }

        if (path === '/api/events') {
          const wanted = url.searchParams.get('session');
          const index = freshIndex(opts.logDir);
          try {
            const rows = index
              ? index.query(wanted === null ? {} : { sessionId: wanted })
              : [];
            json(res, 200, {
              events: rows.map((e) => ({
                seq: e.seq, session_id: e.session_id, ts: e.ts, kind: e.kind, target: e.target,
                outcome: e.outcome, duration_ms: e.duration_ms,
                actor: { human: e.actor_human, agent_id: e.actor_agent_id, tool: e.actor_tool },
                payload_ref: e.payload_ref,
              })),
              sessions: sessions(index),
              checkpoints: readCheckpoints(opts.logDir).length,
            });
          } finally { index?.close(); }
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
          const zip = buildEvidenceBundle(opts.logDir, { report: await verifyNow(opts) });
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
