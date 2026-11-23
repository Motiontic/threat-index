import { describe, expect, it } from 'vitest';
import { check, fetch } from '../src/page';
import { sourceWith } from './examples';
import { makeCtx, reply, route } from './helpers';

describe('page in Node', () => {
  it('throws runtime where HTMLRewriter is missing, and still imports', async () => {
    const source = sourceWith('cert-in');
    const url = source.pull?.page?.url ?? '';
    const h = makeCtx({ source, routes: [route(url, reply('<html></html>'))] });
    await expect(fetch(h.ctx)).rejects.toMatchObject({ code: 'runtime', retryable: false });
    const c = makeCtx({
      source,
      cursor: { kind: 'version', value: 'x', etag: '"e"' },
      routes: [route(url, reply('<html/>'))],
    });
    await expect(check(c.ctx)).rejects.toMatchObject({ code: 'runtime' });
  });
});
