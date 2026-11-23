import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { bodyOf, makeTar, paxRecord } from '../test-support.ts';
import { readTarGz } from './tar.ts';

const read = async (tar: Buffer, limits?: Parameters<typeof readTarGz>[2]) => {
  const seen: { path: string; text: string }[] = [];
  const res = await readTarGz(
    bodyOf(gzipSync(tar)),
    async (e) => {
      seen.push({ path: e.path, text: await e.text() });
    },
    limits,
  );
  return { seen, ...res };
};

describe('readTarGz', () => {
  it('reads files, ignores directories, skips and counts links and climbing paths', async () => {
    const out = await read(
      makeTar([
        { path: 'repo-abc/', type: '5' },
        { path: 'repo-abc/a.json', data: '{"a":1}' },
        { path: 'repo-abc/link', type: '2' },
        { path: '../evil.json', data: 'x' },
        { path: '/abs.json', data: 'x' },
        { path: 'repo-abc/dir/b.txt', data: 'b'.repeat(1000) },
      ]),
    );
    expect(out.seen.map((s) => s.path)).toEqual(['repo-abc/a.json', 'repo-abc/dir/b.txt']);
    expect(out.seen[1]?.text).toHaveLength(1000);
    expect(out).toMatchObject({ files: 2, skipped: 3 });
  });

  it('uses pax and GNU long names', async () => {
    const long = `repo-abc/${'d/'.repeat(80)}file.json`;
    const out = await read(
      makeTar([
        { path: 'PaxHeader', type: 'x', data: paxRecord('path', long) },
        { path: 'short', data: '1' },
        { path: '././@LongLink', type: 'L', data: `${long}2\0` },
        { path: 'short2', data: '2' },
      ]),
    );
    expect(out.seen.map((s) => s.path)).toEqual([long, `${long}2`]);
  });

  it('skips an over-size entry and drains its bytes', async () => {
    const out = await read(
      makeTar([
        { path: 'r/big.json', data: 'x'.repeat(5000) },
        { path: 'r/ok.json', data: 'ok' },
      ]),
      { maxEntryBytes: 1000 },
    );
    expect(out.seen).toEqual([{ path: 'r/ok.json', text: 'ok' }]);
    expect(out.skipped).toBe(1);
  });

  it('skips entries whose text is never read', async () => {
    const seen: string[] = [];
    await readTarGz(
      bodyOf(
        gzipSync(
          makeTar([
            { path: 'r/a.py', data: 'a'.repeat(2000) },
            { path: 'r/b.json', data: 'b' },
          ]),
        ),
      ),
      async (e) => {
        seen.push(e.path);
        if (e.path.endsWith('.json')) expect(await e.text()).toBe('b');
      },
    );
    expect(seen).toEqual(['r/a.py', 'r/b.json']);
  });

  it('fails on a bad checksum, a truncated archive and too many bytes', async () => {
    await expect(read(makeTar([{ path: 'r/a.json', data: 'a', badChecksum: true }]))).rejects.toThrow(
      'bad header checksum',
    );
    const full = makeTar([{ path: 'r/a.json', data: 'a'.repeat(2000) }], { end: false });
    await expect(read(full.subarray(0, 1000))).rejects.toThrow('truncated');
    await expect(
      read(makeTar([{ path: 'r/a.json', data: 'a'.repeat(4000) }]), { maxTotalBytes: 2048 }),
    ).rejects.toThrow('size limit');
  });
});
