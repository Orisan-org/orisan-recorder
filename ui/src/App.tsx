import React, { useCallback, useEffect, useState } from 'react';
import { api, type Banner, type ScanResult, type SessionSummary, type UiEvent, type Status } from './api.js';

type Screen = 'agents' | 'sessions' | 'timeline' | 'evidence';

/**
 * The integrity banner.
 *
 * Every string comes from the server's bannerFor(); nothing reassuring is
 * written here. That is the point: if a component hard-coded "verified", the
 * banner's own tests could not see it, so this renders whatever the tested
 * logic produced and adds no words of its own.
 */
function IntegrityBanner({ banner }: { banner: Banner }): React.JSX.Element {
  return (
    <div className={`banner banner-${banner.tone}`}>
      <div className="head">{banner.headline}</div>
      <div className="detail">{banner.detail}</div>
      {banner.findings.length > 0 && (
        <ul className="findings">
          {banner.findings.slice(0, 6).map((f) => (
            <li key={f.code + f.message}>
              <span className="mono">{f.code}</span> — {f.message}
            </li>
          ))}
        </ul>
      )}
      <div className="more">
        <a href={banner.docsHref} target="_blank" rel="noreferrer">What this does and does not prove</a>
      </div>
    </div>
  );
}

function AgentRow({ surface, path, server, onChanged }: {
  surface: string; path: string | null; server: { name: string; command: string; args: string[]; source: string; pid?: number };
  onChanged: () => void;
}): React.JSX.Element {
  const [attached, setAttached] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!path) return;
    void api.attached(path).then((r) => setAttached(r.attached)).catch(() => undefined);
  }, [path]);

  const toggle = async (): Promise<void> => {
    if (!path) return;
    setBusy(true); setErr(null);
    try {
      if (attached) { await api.detach(path); setAttached(false); }
      else { await api.attach(path); setAttached(true); }
      onChanged();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <tr>
      <td>{server.name}</td>
      <td className="mono">{server.command} {server.args.slice(0, 3).join(' ')}</td>
      <td><span className="tag">{server.source === 'process' ? `pid ${server.pid}` : 'config'}</span></td>
      <td>
        {path ? (
          <>
            <button className={`btn ${attached ? 'btn-on' : ''}`} onClick={() => void toggle()} disabled={busy}>
              {busy ? '…' : attached ? 'Recording' : 'Record'}
            </button>
            {err && <div className="err">{err}</div>}
          </>
        ) : (
          <span className="tag">running — no config to rewrite</span>
        )}
      </td>
    </tr>
  );
}

function Agents({ onChanged }: { onChanged: () => void }): React.JSX.Element {
  const [data, setData] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);

  const rescan = useCallback(() => {
    setLoading(true);
    void api.scan().then(setData).finally(() => setLoading(false));
  }, []);
  useEffect(rescan, [rescan]);

  const total = data?.surfaces.reduce((n, s) => n + s.servers.length, 0) ?? 0;

  return (
    <>
      <h1>Agents</h1>
      <p className="sub">
        Everything on this machine that looks like an AI agent or MCP server — including
        anything nobody told us about.
      </p>

      {loading && <p>Scanning…</p>}

      {!loading && total === 0 && (
        <div className="empty">
          <p>No agents found.</p>
          <button className="btn btn-primary" onClick={rescan}>Scan again</button>
        </div>
      )}

      {!loading && data && data.surfaces.map((s) => (
        <div className="surface" key={`${s.surface}:${s.config_path ?? 'proc'}`}>
          <h3>{s.surface}</h3>
          <div className="path mono">{s.config_path ?? 'discovered by process scan'}</div>
          {s.servers.length === 0 ? (
            <div className="tag">configured, no servers</div>
          ) : (
            <table>
              <thead>
                <tr><th>Server</th><th>Command</th><th>Found via</th><th>Record</th></tr>
              </thead>
              <tbody>
                {s.servers.map((srv) => (
                  <AgentRow key={`${srv.name}:${srv.pid ?? ''}`} surface={s.surface}
                    path={s.config_path} server={srv} onChanged={onChanged} />
                ))}
              </tbody>
            </table>
          )}
        </div>
      ))}

      {!loading && data && data.gaps.length > 0 && (
        <div className="gaps">
          <strong>Not everything could be checked:</strong>
          <ul className="findings">{data.gaps.map((g) => <li key={g}>{g}</li>)}</ul>
        </div>
      )}

      {!loading && total > 0 && (
        <p className="sub" style={{ marginTop: 18 }}>
          <button className="btn" onClick={rescan}>Scan again</button>
        </p>
      )}
    </>
  );
}

/** Sessions are uuids; show enough to tell them apart without the wall of hex. */
function shortId(id: string): string { return id.slice(0, 8); }

function duration(startedAt: string, endedAt: string): string {
  const ms = Date.parse(endedAt) - Date.parse(startedAt);
  if (!Number.isFinite(ms) || ms < 0) return '';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms / 60_000)}m`;
}

function Sessions({ onOpen }: { onOpen: (id: string) => void }): React.JSX.Element {
  const [rows, setRows] = useState<SessionSummary[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { void api.sessions().then((r) => setRows(r.sessions)).finally(() => setLoading(false)); }, []);

  return (
    <>
      <h1>Sessions</h1>
      <p className="sub">One recorder run per row — newest first.</p>
      {loading && <p>Loading…</p>}
      {!loading && rows.length === 0 ? (
        <div className="empty"><p>Nothing recorded yet.</p></div>
      ) : (
        <table>
          <thead>
            <tr><th>Session</th><th>Agent</th><th>Started</th><th>Duration</th><th>Events</th><th>Flagged</th><th /></tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.id} className={s.flagged > 0 ? 'flagged' : ''}>
                <td className="mono" title={s.id}>{shortId(s.id)}</td>
                <td>{s.agents.join(', ')}</td>
                <td>{new Date(s.startedAt).toLocaleString()}</td>
                <td className="mono">{duration(s.startedAt, s.endedAt)}</td>
                <td>{s.events}</td>
                <td>{s.flagged > 0 ? s.flagged : ''}</td>
                <td><button className="btn" onClick={() => onOpen(s.id)}>Open</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

const KIND_ICON: Record<string, string> = {
  model_call: '◆', tool_call: '▸', config_change: '⚙', flag: '▲', redaction: '▨',
};

function EventRows({ events }: { events: UiEvent[] }): React.JSX.Element {
  return (
    <table>
      <thead><tr><th>Time</th><th>Kind</th><th>Summary</th><th>Duration</th></tr></thead>
      <tbody>
        {events.map((e) => (
          <tr key={e.seq} className={e.kind === 'flag' ? 'flagged' : ''}>
            <td className="mono">{new Date(e.ts).toLocaleTimeString()}</td>
            <td>{KIND_ICON[e.kind] ?? '·'} {e.kind}</td>
            <td>
              <span className="mono">{e.target ?? '—'}</span>
              {e.outcome && e.outcome !== 'ok' && <> — {e.outcome}</>}
            </td>
            <td className="mono">{e.duration_ms === null ? '' : `${e.duration_ms}ms`}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Timeline({ banner, sessionId, onClearFilter }: {
  banner: Banner | null; sessionId: string | null; onClearFilter: () => void;
}): React.JSX.Element {
  const [events, setEvents] = useState<UiEvent[]>([]);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    void api.events(sessionId ?? undefined)
      .then((r) => { setEvents(r.events); setSessions(r.sessions); })
      .finally(() => setLoading(false));
  }, [sessionId]);

  // Group in the order the sessions actually ran, oldest first, so the page
  // reads top-to-bottom as time passing.
  const groups = sessions
    .filter((s) => sessionId === null || s.id === sessionId)
    .slice()
    .sort((a, b) => (a.startedAt < b.startedAt ? -1 : 1))
    .map((s) => ({ session: s, events: events.filter((e) => e.session_id === s.id) }))
    .filter((g) => g.events.length > 0);

  return (
    <>
      <h1>Timeline</h1>
      <p className="sub">
        {sessionId === null
          ? 'Every recorded action, grouped by the run that produced it.'
          : <>Session <span className="mono">{shortId(sessionId)}</span> · <button className="btn" onClick={onClearFilter}>Show all sessions</button></>}
      </p>
      {banner && <IntegrityBanner banner={banner} />}
      {loading && <p>Loading…</p>}
      {!loading && events.length === 0 && <div className="empty"><p>No events recorded yet.</p></div>}
      {groups.map((g) => (
        <div className="session-group" key={g.session.id}>
          <div className="session-head">
            <span className="mono id" title={g.session.id}>{shortId(g.session.id)}</span>
            <span>{g.session.agents.join(', ') || 'unknown agent'}</span>
            <span className="meta">
              {new Date(g.session.startedAt).toLocaleString()} · {duration(g.session.startedAt, g.session.endedAt)} ·
              {' '}{g.session.events} events
              {g.session.flagged > 0 && <span className="flag-count"> · {g.session.flagged} flagged</span>}
            </span>
          </div>
          <EventRows events={g.events} />
        </div>
      ))}
    </>
  );
}

function Evidence({ status }: { status: Status | null }): React.JSX.Element {
  return (
    <>
      <h1>Evidence</h1>
      <p className="sub">
        A bundle a third party can check without our software: events, checkpoints,
        timestamp tokens, the public key, and instructions that use openssl.
      </p>
      {status && <IntegrityBanner banner={status.banner} />}
      <p>
        <a className="btn btn-primary" href="/api/export" download>Export bundle (.zip)</a>
      </p>
      {status && (
        <p className="sub">
          {status.events} events · {status.checkpoints} checkpoints · {status.anchored} anchors accepted
          {!status.witnessConfigured && ' · no witness configured'}
        </p>
      )}
      <p className="sub">The signing private key and payload contents are never included.</p>
    </>
  );
}

export function App(): React.JSX.Element {
  const [screen, setScreen] = useState<Screen>('agents');
  const [status, setStatus] = useState<Status | null>(null);
  const [sessionFilter, setSessionFilter] = useState<string | null>(null);

  const refresh = useCallback(() => {
    void api.status().then(setStatus).catch(() => setStatus(null));
  }, []);
  useEffect(refresh, [refresh]);

  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">Orisan Recorder</div>
        <nav className="nav">
          {(['agents', 'sessions', 'timeline', 'evidence'] as Screen[]).map((s) => (
            <button key={s} className={screen === s ? 'on' : ''} onClick={() => {
              if (s === 'timeline' && screen !== 'timeline') setSessionFilter(null);
              setScreen(s);
            }}>
              {s[0]!.toUpperCase() + s.slice(1)}
            </button>
          ))}
        </nav>
      </aside>
      <main className="main">
        {screen === 'agents' && <Agents onChanged={refresh} />}
        {screen === 'sessions' && <Sessions onOpen={(id) => { setSessionFilter(id); setScreen('timeline'); }} />}
        {screen === 'timeline' && (
          <Timeline banner={status?.banner ?? null} sessionId={sessionFilter}
            onClearFilter={() => setSessionFilter(null)} />
        )}
        {screen === 'evidence' && <Evidence status={status} />}
      </main>
    </div>
  );
}
