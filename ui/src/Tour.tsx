import React, { useState } from 'react';

/**
 * First run only. Three cards, no jargon, and it can be dismissed at any point.
 *
 * The last card is the one that matters: it says what the tool cannot do,
 * before anyone has had a chance to assume otherwise.
 */
const CARDS = [
  {
    title: 'This writes down what your AI agents do',
    body:
      'Every action an agent takes — the questions it puts to a model, the tools it uses — gets written to a '
      + 'local file on this machine. Nothing is sent anywhere. Nothing is recorded until you switch it on for a '
      + 'specific agent.',
  },
  {
    title: 'The records are built so edits show up',
    body:
      'Each record is written with a short code calculated from its contents. Change a record later and the code '
      + 'stops matching, so the change is visible rather than silent. Batches of records are summarised, signed, '
      + 'and stamped by an outside timestamping service.',
  },
  {
    title: 'What it cannot do — worth knowing now',
    body:
      'It can only show what reached the recorder: an agent nobody connected leaves no trace here. And on its own '
      + 'it cannot prove nothing was deleted from the end of the log, because what is left still looks consistent. '
      + 'Setting up a witness fixes that second one: run `orisan-rec witness register <log dir>`, which uses '
      + 'https://witness.orisan.org — a witness Orisan runs, so it defends against tampering by whoever holds '
      + 'this machine, not against Orisan. Pass --url to use one we do not run. The banner on Timeline and '
      + 'Evidence tells you which of these applies.',
  },
];

const SEEN_KEY = 'orisan.tour.seen.v1';

export function Tour({ onDone }: { onDone: () => void }): React.JSX.Element | null {
  const [i, setI] = useState(0);
  const card = CARDS[i]!;

  const finish = (): void => {
    try { window.localStorage.setItem(SEEN_KEY, '1'); } catch { /* private mode is fine */ }
    onDone();
  };

  return (
    <div className="tour" role="dialog" aria-label="Welcome">
      <div className="tour-card">
        <h2>{card.title}</h2>
        <p>{card.body}</p>
        <div className="tour-actions">
          <span className="tour-dots">{i + 1} of {CARDS.length}</span>
          <button className="btn" onClick={finish}>Skip</button>
          {i < CARDS.length - 1
            ? <button className="btn btn-primary" onClick={() => setI(i + 1)}>Next</button>
            : <button className="btn btn-primary" onClick={finish}>Start</button>}
        </div>
      </div>
    </div>
  );
}

export function tourAlreadySeen(): boolean {
  try { return window.localStorage.getItem(SEEN_KEY) === '1'; } catch { return true; }
}
