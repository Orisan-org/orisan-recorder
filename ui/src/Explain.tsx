import React, { useState } from 'react';
import type { GlossaryEntry, ScreenCopy } from './api.js';

/**
 * A technical word with its plain-English meaning on hover.
 *
 * The rule from the spec: every technical term either gets an explanation or
 * gets cut. This is the "gets an explanation" half — the copy itself is
 * policed by tests so the other half cannot rot.
 */
export function Term({ term, glossary, children }: {
  term: string; glossary: GlossaryEntry[]; children?: React.ReactNode;
}): React.JSX.Element {
  const entry = glossary.find((g) => g.term.toLowerCase() === term.toLowerCase());
  if (!entry) return <>{children ?? term}</>;
  return <abbr className="term" title={entry.plain}>{children ?? term}</abbr>;
}

/** Wrap known glossary words in a sentence so hovering explains them. */
export function Annotated({ text, glossary }: { text: string; glossary: GlossaryEntry[] }): React.JSX.Element {
  if (glossary.length === 0) return <>{text}</>;
  const pattern = new RegExp(`\\b(${glossary.map((g) => g.term).join('|')})\\b`, 'gi');
  const out: React.ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(<Term key={`${m.index}`} term={m[0]} glossary={glossary}>{m[0]}</Term>);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return <>{out}</>;
}

/** Every screen says what it is for, with a longer version a click away. */
export function ScreenHeader({ copy, glossary }: { copy: ScreenCopy; glossary: GlossaryEntry[] }): React.JSX.Element {
  const [open, setOpen] = useState(false);
  return (
    <>
      <h1>{copy.title}</h1>
      <p className="screen-what"><Annotated text={copy.what} glossary={glossary} /></p>
      <button className="screen-more" onClick={() => setOpen(!open)}>
        {open ? 'Less' : 'What is this screen for?'}
      </button>
      {open && (
        <div className="screen-detail"><Annotated text={copy.detail} glossary={glossary} /></div>
      )}
    </>
  );
}
