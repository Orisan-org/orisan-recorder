# media

Everything here was produced by a real run. Nothing is staged, re-cut, or
edited after the fact.

## Discovery runs against a fabricated home directory

Step 1 of the showcase, and the Agents screen, read a real machine. A published
recording of a real machine is an inventory of its owner: username, every
installed MCP client, project directory names, and live process ids. The first
version of these files was exactly that.

So the published artefacts scan `test/fixtures/demo-home` — copied to
`/tmp/orisan-demo-home` so the paths on screen carry no username — and the
recording **says so on screen** while it does it. `orisan-rec scan` with no
arguments reads your actual machine; that is the real behaviour and it is
unchanged.

`--no-processes` skips the process probe, and the scan reports that as a gap,
so the recording shows a probe that did not run rather than quietly omitting
it. That gap is visible in the recording and in the Agents screenshot.

    cp -R test/fixtures/demo-home /tmp/orisan-demo-home

## showcase.cast / showcase.gif

`orisan-rec showcase` recorded with asciinema against the hosted witness at
`witness.orisan.org` and a real RFC 3161 timestamp from `freetsa.org`. One take.

    npm run build
    asciinema rec media/showcase.cast --overwrite --window-size 128x40 \
      -c "node dist/cli.js showcase --scan-home /tmp/orisan-demo-home \
          --pause 1400 --dir /tmp/orisan-demo"
    agg --theme monokai --font-size 15 media/showcase.cast media/showcase.gif

The showcase exits non-zero and prints SHOWCASE FAILED if any step misbehaves,
so a recording that completes is a recording of a passing run.

## The five screenshots

| File | What it shows |
|---|---|
| `1-agents.png` | Discovery — the fabricated root, and the gap for the probe that was skipped |
| `2-verified.png` | Green banner, expanded: what was checked **and** what it does not mean |
| `3-event-detail.png` | One action opened up: what the agent was given, what it decided, and the record's own code |
| `4-tampered.png` | Red banner after the tail was deleted, naming the missing checkpoint |
| `5-prove-it.png` | Prove it, run against the user's own log: both attacks caught |

Regenerate:

    node media/capture.mjs <greenLogDir> <tamperedLogDir> <tsaCa> "" /tmp/orisan-demo-home

`capture.mjs` asserts the banner tone before saving — it throws if the "green"
page is not green or the "tampered" page is not red, so a screenshot cannot
quietly show the wrong state. Both logs must be real: the first verifying CLEAN
against the hosted witness, the second left TAMPERED by `showcase`.

## The guard

`test/media-scrub.test.ts` fails if any committed media contains this machine's
home directory or username, if the cast shows a home path other than a
fabricated one, if it carries process ids, or if it stops stating that
discovery ran against a fabricated root. Images are covered transitively — the
GIF is rendered from the cast, and their text is pixels no byte scan can read.
