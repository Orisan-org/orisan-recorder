/**
 * A fake model provider. Answers Anthropic- and OpenAI-shaped requests, both
 * buffered and streaming. No network, no keys, no real provider.
 */
import { createServer, type Server } from 'node:http';

export interface FakeApi {
  url: string;
  close: () => Promise<void>;
  /** Requests seen, so a test can assert the tap forwarded faithfully. */
  seen: { path: string; body: string; auth: string | undefined }[];
  /** Set to have the next response take this long before its first byte. */
  delayMs: number;
}

export function startFakeModelApi(): Promise<FakeApi> {
  const seen: FakeApi['seen'] = [];
  const state = { delayMs: 0 };

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      seen.push({ path: req.url ?? '', body, auth: req.headers['authorization'] as string | undefined });

      const send = (): void => {
        let doc: Record<string, unknown> = {};
        try { doc = JSON.parse(body) as Record<string, unknown>; } catch { /* echo shape below */ }
        const wantsStream = doc['stream'] === true;
        const openai = (req.url ?? '').includes('chat/completions');

        if (!wantsStream) {
          const payload = openai
            ? {
                id: 'chatcmpl-fake', object: 'chat.completion', model: doc['model'] ?? 'fake',
                choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'fake completion text' } }],
                usage: { prompt_tokens: 120, completion_tokens: 8 },
              }
            : {
                id: 'msg_fake', type: 'message', role: 'assistant', model: doc['model'] ?? 'fake',
                content: [
                  { type: 'text', text: 'fake completion text' },
                  { type: 'tool_use', id: 'tu_1', name: 'fake_lookup', input: { q: 'x' } },
                ],
                stop_reason: 'tool_use',
                usage: { input_tokens: 120, output_tokens: 8 },
              };
          const out = Buffer.from(JSON.stringify(payload));
          res.writeHead(200, { 'content-type': 'application/json', 'content-length': out.length });
          res.end(out);
          return;
        }

        res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
        const frames = openai
          ? [
              { choices: [{ index: 0, delta: { content: 'fake ' } }] },
              { choices: [{ index: 0, delta: { content: 'stream' } }] },
              { choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] },
            ]
          : [
              { type: 'message_start', message: { usage: { input_tokens: 120 } } },
              { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
              { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'fake ' } },
              { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'stream' } },
              { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 6 } },
            ];
        for (const f of frames) res.write(`data: ${JSON.stringify(f)}\n\n`);
        res.write('data: [DONE]\n\n');
        res.end();
      };

      if (state.delayMs > 0) setTimeout(send, state.delayMs);
      else send();
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise<void>((d) => { server.close(() => d()); }),
        seen,
        get delayMs() { return state.delayMs; },
        set delayMs(v: number) { state.delayMs = v; },
      } as FakeApi);
    });
  });
}
