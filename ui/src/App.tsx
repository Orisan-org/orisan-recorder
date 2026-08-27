import React, { useCallback, useEffect, useState } from 'react';
import { plural } from './plural.js';
import {
  api, type Banner, type EventDetail, type GlossaryEntry, type ScanResult,
  type ScreenCopy, type ScreenName, type SessionSummary, type Status, type UiEvent,
} from './api.js';
import { Annotated, ScreenHeader } from './Explain.js';
import { Tour, tourAlreadySeen } from './Tour.js';
import { WhyTrust } from './WhyTrust.js';

type Screen = ScreenName;

/**
 * The integrity banner.
 *
 * Every string comes from the server's bannerFor(); nothing reassuring is
 * written here. That is the point: if a component hard-coded "verified", the
 * banner's own tests could not see it, so this renders whatever the tested
 * logic produced and adds no words of its own.
 */
function IntegrityBanner({ banner, glossary }: { banner: Banner; glossary: GlossaryEntry[] }): React.JSX.Element {
  const [open, setOpen] = useState(false);
  return (
    <div className={`banner banner-${banner.tone}`} onClick={() => setOpen(!open)}
      role="button" tabIndex={0}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setOpen(!open); }}>
      <div className="head">{banner.headline}</div>
      <div className="detail"><Annotated text={banner.detail} glossary={glossary} /></div>

      {/* Red's detail IS the first finding in plain English, so listing it
          again directly underneath reads as a stutter. Show only findings the
          headline sentence has not already said. */}
      {banner.findings.filter((f) => f.plain !== banner.detail).length > 0 && (
        <ul className="findings">
          {banner.findings.filter((f) => f.plain !== banner.detail).slice(0, 6).map((f) => (
            <li key={f.code + f.message}><Annotated text={f.plain} glossary={glossary} /></li>
          ))}
        </ul>
      )}

      <div className="toggle">{open ? 'Hide what was checked ▲' : 'What was checked, and what was not ▼'}</div>

      {open && (
        <div className="banner-detail" onClick={(e) => e.stopPropagation()}>
          <h4>What this means</h4>
          <ul>{banner.means.map((m) => <li key={m}><Annotated text={m} glossary={glossary} /></li>)}</ul>
          <h4>What it does not mean</h4>
          <ul>{banner.doesNotMean.map((m) => <li key={m}><Annotated text={m} glossary={glossary} /></li>)}</ul>
          {banner.findings.length > 0 && (
            <>
              <h4>Technical detail</h4>
              <ul>
                {banner.findings.map((f) => (
                  <li key={f.code}><span className="mono">{f.code}</span> — {f.message}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}

/** One expanded event: what the agent saw, decided, and got back. */
function EventExpansion({ seq, glossary }: { seq: number; glossary: GlossaryEntry[] }): React.JSX.Element {
  const [detail, setDetail] = useState<EventDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { void api.eventDetail(seq).then(setDetail).catch((e: Error) => setErr(e.message)); }, [seq]);

  if (err) return <div className="expand-inner err">Could not load: {err}</div>;
  if (!detail) return <div className="expand-inner ctx-note">Loading…</div>;

  const { event, contextState, context } = detail;
  const ctx = context as { request?: unknown; response?: unknown } | null;

  const contextNote: Record<string, string> = {
    not_captured: 'No context was captured for this action. Model calls capture context only when the tap is running with an encryption key.',
    locked: 'The context was captured and encrypted. Start the interface with the payload key to read it here.',
    unreadable: 'The context is stored but could not be decrypted with the key provided.',
    none: 'This kind of action does not carry context.',
  };

  return (
    <div className="expand-inner">
      <dl className="expand-grid">
        <dt>What it was</dt>
        <dd>{event.kind === 'model_call' ? 'A question put to a model' : event.kind === 'tool_call' ? 'A tool the agent used' : event.kind}
          {event.target ? <> — <span className="mono">{event.target}</span></> : null}</dd>

        <dt>What came back</dt>
        <dd>{event.outcome ?? '—'}</dd>

        <dt>How long</dt>
        <dd>{event.duration_ms === null ? '—' : `${event.duration_ms}ms`}</dd>

        <dt>On whose behalf</dt>
        <dd>{event.actor.human ?? 'unknown'} · <span className="mono">{event.actor.tool ?? event.actor.agent_id}</span></dd>

        <dt>This record's code</dt>
        <dd className="mono" title="Calculated from this record's contents. If the record is edited, this stops matching.">
          {event.hash}
        </dd>

        <dt>Follows on from</dt>
        <dd className="mono" title="The code of the record before this one. This is what links the records into a run.">
          {event.prev_hash}
        </dd>
      </dl>

      <h4 style={{ margin: '14px 0 6px', fontSize: 12, textTransform: 'uppercase', letterSpacing: '.05em', color: 'var(--muted)' }}>
        What the agent saw and decided
      </h4>
      {contextState === 'unlocked' && ctx ? (
        <>
          <div className="ctx-note" style={{ marginBottom: 4 }}>Given to the model:</div>
          <pre className="ctx">{JSON.stringify(ctx.request, null, 2)}</pre>
          <div className="ctx-note" style={{ margin: '8px 0 4px' }}>What the model decided:</div>
          <pre className="ctx">{JSON.stringify(ctx.response, null, 2)}</pre>
        </>
      ) : (
        <p className="ctx-note">
          <Annotated text={contextNote[contextState] ?? contextNote['none']!} glossary={glossary} />
        </p>
      )}
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

function Agents({ onChanged, copy, glossary }: {
  onChanged: () => void; copy: ScreenCopy; glossary: GlossaryEntry[];
}): React.JSX.Element {
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
      <ScreenHeader copy={copy} glossary={glossary} />

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

function Sessions({ onOpen, copy, glossary }: {
  onOpen: (id: string) => void; copy: ScreenCopy; glossary: GlossaryEntry[];
}): React.JSX.Element {
  const [rows, setRows] = useState<SessionSummary[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { void api.sessions().then((r) => setRows(r.sessions)).finally(() => setLoading(false)); }, []);

  return (
    <>
      <ScreenHeader copy={copy} glossary={glossary} />
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

function EventRows({ events, glossary }: { events: UiEvent[]; glossary: GlossaryEntry[] }): React.JSX.Element {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <table>
      <thead><tr><th>Time</th><th>Kind</th><th>Summary</th><th>Duration</th></tr></thead>
      <tbody>
        {events.map((e) => (
          <React.Fragment key={e.seq}>
            <tr className={`clickable ${e.kind === 'flag' ? 'flagged' : ''} ${open === e.seq ? 'row-open' : ''}`}
              onClick={() => setOpen(open === e.seq ? null : e.seq)}>
              <td className="mono">{new Date(e.ts).toLocaleTimeString()}</td>
              <td>{KIND_ICON[e.kind] ?? '·'} {e.kind}</td>
              <td>
                <span className="mono">{e.target ?? '—'}</span>
                {e.outcome && e.outcome !== 'ok' && <> — {e.outcome}</>}
              </td>
              <td className="mono">{e.duration_ms === null ? '' : `${e.duration_ms}ms`}</td>
            </tr>
            {open === e.seq && (
              <tr className="expand"><td colSpan={4}><EventExpansion seq={e.seq} glossary={glossary} /></td></tr>
            )}
          </React.Fragment>
        ))}
      </tbody>
    </table>
  );
}

function Timeline({ banner, sessionId, onClearFilter, copy, glossary }: {
  banner: Banner | null; sessionId: string | null; onClearFilter: () => void;
  copy: ScreenCopy; glossary: GlossaryEntry[];
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
      <ScreenHeader copy={copy} glossary={glossary} />
      {sessionId !== null && (
        <p className="sub">
          Showing one run: <span className="mono">{shortId(sessionId)}</span>{' '}
          <button className="btn" onClick={onClearFilter}>Show all runs</button>
        </p>
      )}
      <p className="ctx-note" style={{ marginTop: -4 }}>Click any row to see what the agent was given and what it decided.</p>
      {banner && <IntegrityBanner banner={banner} glossary={glossary} />}
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
          <EventRows events={g.events} glossary={glossary} />
        </div>
      ))}
    </>
  );
}

function Evidence({ status, copy, glossary }: {
  status: Status | null; copy: ScreenCopy; glossary: GlossaryEntry[];
}): React.JSX.Element {
  return (
    <>
      <ScreenHeader copy={copy} glossary={glossary} />
      {status && <IntegrityBanner banner={status.banner} glossary={glossary} />}
      <p>
        <a className="btn btn-primary" href="/api/export" download>Export bundle (.zip)</a>
      </p>
      {status && (
        <p className="sub">
          {plural(status.events, 'event')} · {plural(status.checkpoints, 'checkpoint')} · {plural(status.anchored, 'anchor')} accepted
          {!status.witnessConfigured && ' · no witness configured'}
        </p>
      )}
      <p className="sub">
        The bundle includes a README written for whoever receives it, explaining what these records prove and — more
        importantly — what they do not. Your signing key and the contents of anything recorded are never included.
      </p>
    </>
  );
}

export function App(): React.JSX.Element {
  const [screen, setScreen] = useState<Screen>('agents');
  const [status, setStatus] = useState<Status | null>(null);
  const [sessionFilter, setSessionFilter] = useState<string | null>(null);
  const [screens, setScreens] = useState<Record<ScreenName, ScreenCopy> | null>(null);
  const [glossary, setGlossary] = useState<GlossaryEntry[]>([]);
  const [showTour, setShowTour] = useState(false);

  useEffect(() => {
    void api.explain().then((r) => { setScreens(r.screens); setGlossary(r.glossary); }).catch(() => undefined);
    setShowTour(!tourAlreadySeen());
  }, []);

  const refresh = useCallback(() => {
    void api.status().then(setStatus).catch(() => setStatus(null));
  }, []);
  useEffect(refresh, [refresh]);

  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">Orisan Recorder</div>
        <nav className="nav">
          {(['agents', 'sessions', 'timeline', 'evidence', 'trust'] as Screen[]).map((s) => (
            <button key={s} className={screen === s ? 'on' : ''} onClick={() => {
              if (s === 'timeline' && screen !== 'timeline') setSessionFilter(null);
              setScreen(s);
            }}>
              {s === 'trust' ? 'Why trust this?' : s[0]!.toUpperCase() + s.slice(1)}
            </button>
          ))}
        </nav>
      </aside>
      <main className="main">
        {screens && (
          <>
            {screen === 'agents' && <Agents onChanged={refresh} copy={screens.agents} glossary={glossary} />}
            {screen === 'sessions' && (
              <Sessions onOpen={(id) => { setSessionFilter(id); setScreen('timeline'); }}
                copy={screens.sessions} glossary={glossary} />
            )}
            {screen === 'timeline' && (
              <Timeline banner={status?.banner ?? null} sessionId={sessionFilter}
                onClearFilter={() => setSessionFilter(null)} copy={screens.timeline} glossary={glossary} />
            )}
            {screen === 'evidence' && <Evidence status={status} copy={screens.evidence} glossary={glossary} />}
            {screen === 'trust' && <WhyTrust copy={screens.trust} glossary={glossary} />}
          </>
        )}
      </main>
      {showTour && <Tour onDone={() => setShowTour(false)} />}
    </div>
  );
}
