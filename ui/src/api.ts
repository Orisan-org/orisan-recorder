export interface Banner {
  tone: 'green' | 'red' | 'grey';
  headline: string;
  detail: string;
  docsHref: string;
  findings: { code: string; message: string; plain: string }[];
  means: string[];
  doesNotMean: string[];
}

export interface GlossaryEntry { term: string; plain: string }
export interface ScreenCopy { title: string; what: string; detail: string }
export type ScreenName = 'agents' | 'sessions' | 'timeline' | 'evidence' | 'trust';

export interface EventDetail {
  event: {
    seq: number; session_id: string; ts: string; kind: string; target: string | null;
    outcome: string | null; duration_ms: number | null;
    actor: { human: string | null; agent_id: string; tool: string | null };
    args_digest: string | null; payload_ref: string | null;
    hash: string; prev_hash: string;
  };
  contextState: 'none' | 'not_captured' | 'locked' | 'unlocked' | 'unreadable';
  context: unknown;
}

export interface ProofStep { title: string; did: string; result: string; detected: boolean | null; codes: string[] }
export interface ProofRun {
  attack: 'edit' | 'delete_tail'; title: string; premise: string;
  steps: ProofStep[]; verdict: string; detected: boolean;
}
export interface ProveResult {
  ranAt: string; events: number; checkpoints: number; witnessConfigured: boolean;
  baseline: { verdict: string; exitCode: number };
  runs: ProofRun[]; sourceUntouched: boolean;
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
  explain: () => get<{ screens: Record<ScreenName, ScreenCopy>; glossary: GlossaryEntry[] }>('/api/explain'),
  eventDetail: (seq: number) => get<EventDetail>(`/api/events/${seq}`),
  prove: () => post<ProveResult>('/api/prove', {}),
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
