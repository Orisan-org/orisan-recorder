/**
 * Child process for the kill -9 crash test. Appends events as fast as it can,
 * with fsync on, until it is killed. Prints nothing on the happy path so the
 * parent can watch the segment file instead.
 */
import { EventStore } from '../../src/store.js';

const dir = process.argv[2];
if (!dir) throw new Error('usage: appender.ts <dir>');

const { store } = EventStore.open(dir, { maxEventsPerSegment: 100_000, fsync: true });

for (let i = 0; ; i++) {
  store.append({
    actor: { human: 'alice', agent_id: 'spiffe://orisan/agent/crash', tool: 'test' },
    kind: 'tool_call',
    target: `tool.${i}`,
    args_digest: null,
    payload_ref: null,
    outcome: 'ok',
    duration_ms: 1,
  });
}
