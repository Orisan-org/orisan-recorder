export interface Banner {
  tone: 'green' | 'red' | 'grey';
  headline: string;
  detail: string;
  docsHref: string;
  findings: { code: string; message: string }[];
}

export interface Status {
  logDir: string;
  banner: Banner;
  exitCode: number;
  events: number;
  checkpoints: number;
  anchored: number;
  witnessConfigured: boolean;
}

export interface Server {
  name: string; command: string; args: string[];
  source: 'config' | 'process'; pid?: number;
}
export interface Surface { surface: string; config_path: string | null; servers: Server[] }
export interface ScanResult { scanned_at: string; platform: string; home: string; surfaces: Surface[]; gaps: string[] }

export interface SessionSummary {
  id: string; startedAt: string; endedAt: string;
  events: number; flagged: number; agents: string[];
  firstSeq: number; lastSeq: number;
}

export interface UiEvent {
  seq: number; session_id: string; ts: string; kind: string; target: string | null;
  outcome: string | null; duration_ms: number | null;
  actor: { human: string | null; agent_id: string; tool: string | null };
  args_digest: string | null;
}

async function get<T>(path: string): Promise<T> {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return (await r.json()) as T;
}
async function post<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  const data = (await r.json()) as T & { error?: string };
  if (!r.ok) throw new Error(data.error ?? `${path}: ${r.status}`);
  return data;
}

export const api = {
  status: () => get<Status>('/api/status'),
  scan: () => get<ScanResult>('/api/scan'),
  events: (sessionId?: string) => get<{ events: UiEvent[]; sessions: SessionSummary[]; checkpoints: number }>(
    sessionId === undefined ? '/api/events' : `/api/events?session=${encodeURIComponent(sessionId)}`,
  ),
  sessions: () => get<{ sessions: SessionSummary[] }>('/api/sessions'),
  attached: (config: string) => get<{ attached: boolean }>(`/api/attached?config=${encodeURIComponent(config)}`),
  attach: (config: string) => post<{ rewritten: string[]; skipped: string[]; note: string }>('/api/attach', { config }),
  detach: (config: string) => post<{ byteIdentical: boolean }>('/api/detach', { config }),
};
