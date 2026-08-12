/**
 * A minimal fake MCP server over stdio. Answers initialize and tools/call with
 * newline-delimited JSON-RPC. No real MCP SDK, no network, no side effects.
 */
import { createInterface } from 'node:readline';

const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }

  if (msg.method === 'initialize') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: msg.id,
      result: { protocolVersion: '2024-11-05', serverInfo: { name: 'fake', version: '0.0.1' } },
    }) + '\n');
    return;
  }
  if (msg.method === 'tools/call') {
    const name = msg.params?.name;
    if (name === 'explode') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0', id: msg.id,
        result: { isError: true, content: [{ type: 'text', text: 'fake failure' }] },
      }) + '\n');
      return;
    }
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: msg.id,
      result: { content: [{ type: 'text', text: `fake result for ${name}` }] },
    }) + '\n');
    return;
  }
  if (msg.method === 'shutdown') { rl.close(); }
});
rl.on('close', () => process.exit(0));
