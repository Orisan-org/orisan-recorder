/**
 * A standalone writer, run as a real child process by test/lock.test.ts.
 *
 * The bug this guards against is between PROCESSES: two `EventStore` instances
 * in one process would share nothing that matters, so an in-process test would
 * pass while the real failure stayed wide open. Hence a separate entry point.
 *
 *   tsx concurrent-writer.ts <dir> <tag> <count> [holdMs]
 *
 * Prints one JSON line describing what happened, so the parent can assert on
 * the refusal rather than on an exit code alone.
 */
import { EventStore } from '../../src/store.js';
import { LogDirectoryLockedError } from '../../src/lock.js';

const [dir, tag, countRaw, holdRaw] = process.argv.slice(2);
const count = Number.parseInt(countRaw ?? '20', 10);
const holdMs = Number.parseInt(holdRaw ?? '0', 10);

const say = (o: Record<string, unknown>): void => { process.stdout.write(`${JSON.stringify({ tag, ...o })}\n`); };

let store: EventStore | null = null;
try {
  store = EventStore.open(dir!, { fsync: false }).store;
} catch (e) {
  if (e instanceof LogDirectoryLockedError) {
    say({ result: 'refused', reason: e.reason, holderPid: e.holder?.pid ?? null, message: e.message });
    process.exit(3);
  }
  say({ result: 'error', message: (e as Error).message });
  process.exit(4);
}

try {
  for (let i = 0; i < count; i++) {
    store.append({
      actor: { human: 'tester', agent_id: `writer-${tag}`, tool: 'vitest' },
      kind: 'tool_call',
      target: `read_file:/tmp/${tag}/${i}.ts`,
      args_digest: null,
      payload_ref: null,
      outcome: 'ok',
      duration_ms: null,
    });
    if (holdMs > 0 && i === 0) await new Promise((r) => setTimeout(r, holdMs));
  }
  say({ result: 'wrote', count, head: store.head.seq });
  store.close();
  process.exit(0);
} catch (e) {
  say({ result: 'append_failed', message: (e as Error).message });
  store.close();
  process.exit(5);
}
