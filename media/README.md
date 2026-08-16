# media

Everything here was produced by a real run. Nothing is staged, re-cut, or
edited after the fact.

## showcase.cast / showcase.gif

`orisan-rec showcase` recorded with asciinema against the hosted witness at
`witness.orisan.org` and a real RFC 3161 timestamp from `freetsa.org`. 45
seconds, one take.

Regenerate:

    npm run build
    asciinema rec media/showcase.cast --overwrite --window-size 128x40 \
      -c "node dist/cli.js showcase --pause 1400 --dir /tmp/orisan-demo"
    agg --theme monokai --font-size 15 media/showcase.cast media/showcase.gif

The showcase exits non-zero and prints SHOWCASE FAILED if any step misbehaves,
so a recording that completes is a recording of a passing run.

## The five screenshots

| File | What it shows |
|---|---|
| `1-agents.png` | Discovery — real MCP servers found on the machine, including ones from stray config files |
| `2-verified.png` | Green banner, expanded: what was checked **and** what it does not mean |
| `3-event-detail.png` | One action opened up: what the agent was given, what it decided, and the record's own code |
| `4-tampered.png` | Red banner after the tail was deleted, naming the missing checkpoint |
| `5-prove-it.png` | Prove it, run against the user's own log: both attacks caught |

Regenerate:

    node media/capture.mjs <greenLogDir> <tamperedLogDir> <tsaCa> [payloadKey]

`capture.mjs` asserts the banner tone before saving — it throws if the "green"
page is not green or the "tampered" page is not red, so a screenshot cannot
quietly show the wrong state. Both logs must be real: the first verifying CLEAN
against the hosted witness, the second left TAMPERED by `showcase`.
