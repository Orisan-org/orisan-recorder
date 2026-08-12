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

export interface UiEvent {
  seq: number; ts: string; kind: string; target: string | null;
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
  events: () => get<{ events: UiEvent[]; checkpoints: number }>('/api/events'),
  sessions: () => get<{ sessions: { id: string; startedAt: string; endedAt: string; events: number; flagged: number }[] }>('/api/sessions'),
  attached: (config: string) => get<{ attached: boolean }>(`/api/attached?config=${encodeURIComponent(config)}`),
  attach: (config: string) => post<{ rewritten: string[]; skipped: string[]; note: string }>('/api/attach', { config }),
  detach: (config: string) => post<{ byteIdentical: boolean }>('/api/detach', { config }),
};
