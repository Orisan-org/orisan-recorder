import React, { useEffect, useState } from 'react';
import { api, type GlossaryEntry, type ProveResult, type ScreenCopy, type SetupStep } from './api.js';
import { Annotated, ScreenHeader } from './Explain.js';

/**
 * "Why trust this?" — the page that has to survive a sceptical reader.
 *
 * Each claim states its limit next to it, and Prove it runs the real attack on
 * the user's own log rather than replaying a recording. When the attack is NOT
 * caught, the page says so plainly; that outcome is the honest one and hiding
 * it would undo the point of the page.
 */
export function WhyTrust({ copy, glossary }: { copy: ScreenCopy; glossary: GlossaryEntry[] }): React.JSX.Element {
  const [steps, setSteps] = useState<SetupStep[]>([]);
  const [result, setResult] = useState<ProveResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { void api.setup().then((r) => setSteps(r.steps)).catch(() => undefined); }, []);

  const run = async (): Promise<void> => {
    setRunning(true); setError(null);
    try { setResult(await api.prove()); }
    catch (e) { setError((e as Error).message); }
    finally { setRunning(false); }
  };

  return (
    <>
      <ScreenHeader copy={copy} glossary={glossary} />

      <h2 style={{ fontSize: 15, marginTop: 24 }}>What these records can show you</h2>
      <ul className="findings" style={{ maxWidth: '68ch', lineHeight: 1.6 }}>
        <li><strong>That nothing was edited.</strong> Every action is written with a short code taken from its
          contents. Change it later and the code stops matching.</li>
        <li><strong>That nothing was quietly removed from the middle.</strong> Each record also carries the code of
          the one before it, so a gap breaks the run.</li>
        <li><strong>That a batch existed by a certain time.</strong> Batches are stamped by an outside{' '}
          <Annotated text="timestamp authority" glossary={glossary} />, and you check that stamp with openssl
          rather than with our software.</li>
        <li><strong>That nothing was removed from the end</strong> — but only if a{' '}
          <Annotated text="witness" glossary={glossary} /> is set up. This is the one a log genuinely cannot do
          alone.</li>
      </ul>

      <h2 style={{ fontSize: 15, marginTop: 24 }}>What they cannot show you</h2>
      <ul className="findings" style={{ maxWidth: '68ch', lineHeight: 1.6 }}>
        <li><strong>That everything was recorded.</strong> We can only show what reached the recorder. An agent
          nobody connected leaves no trace here, and no amount of checking would reveal it.</li>
        <li><strong>That what happened was allowed.</strong> These are records of actions, not judgements about
          them.</li>
        <li><strong>Who did something.</strong> The records show what changed, not who changed it.</li>
      </ul>

      {steps.length > 0 && steps.some((s) => !s.done) && (
        <>
          <h2 style={{ fontSize: 15, marginTop: 24 }}>What would make this green</h2>
          <p className="screen-what">
            The banner is grey because of the unfinished steps below. Grey is not a warning — it means one of these
            has not been done yet.
          </p>
          <ol className="setup-list">
            {steps.map((s) => (
              <li key={s.label} className={s.done ? 'done' : ''}>
                <span className="setup-mark">{s.done ? '✓' : '○'}</span>
                <span>
                  <strong>{s.label}</strong>
                  <div className="ctx-note"><Annotated text={s.why} glossary={glossary} /></div>
                  {!s.done && s.command && <div className="mono setup-cmd">{s.command}</div>}
                </span>
              </li>
            ))}
          </ol>
        </>
      )}

      <h2 style={{ fontSize: 15, marginTop: 26 }}>Prove it</h2>
      <p className="screen-what">
        This attacks a copy of your own log, right now, and shows you what the checker says. Your real records are
        not touched.
      </p>
      <p>
        <button className="btn btn-primary" onClick={() => void run()} disabled={running}>
          {running ? 'Running…' : 'Prove it on my log'}
        </button>
      </p>

      {error && <p className="err">Could not run: {error}</p>}

      {result && (
        <>
          <p className="sub">
            Ran against {result.events} recorded action(s) and {result.checkpoints} batch summaries.{' '}
            {result.sourceUntouched
              ? 'Your log is byte-for-byte as it was before this ran.'
              : 'WARNING: the source log changed during this run — please report this.'}
          </p>

          {result.runs.map((r) => (
            <div className="prove-run" key={r.attack}>
              <h3>{r.title}</h3>
              <div className="prove-body">
                <p className="ctx-note" style={{ marginTop: 0 }}>{r.premise}</p>
                {r.steps.map((s, i) => (
                  <div className="prove-step" key={i}>
                    <span className={`mark ${s.detected === true ? 'mark-yes' : 'mark-no'}`}>
                      {s.detected === true ? '✓' : s.detected === false ? '·' : '›'}
                    </span>
                    <span>
                      <strong>{s.title}.</strong> {s.did}<br />
                      <span className="ctx-note">{s.result}</span>
                    </span>
                  </div>
                ))}
                <div className={`prove-verdict ${r.detected ? 'verdict-caught' : 'verdict-open'}`}>
                  {r.verdict}
                </div>
              </div>
            </div>
          ))}
        </>
      )}
    </>
  );
}
