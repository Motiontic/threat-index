/**
 * A streaming reader for gzipped tar archives (ustar, pax, GNU long names). Nothing is written to disk and
 * nothing is held beyond the entry being read.
 */
import { Readable } from 'node:stream';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { createGunzip } from 'node:zlib';

export interface TarEntry {
  path: string;
  size: number;
  /** Reads the entry's bytes as UTF-8. If `onEntry` never calls it, the entry is skipped unread. */
  text(): Promise<string>;
}

export interface TarLimits {
  maxEntryBytes?: number;
  maxTotalBytes?: number;
}

export const MAX_ENTRY_BYTES = 10 * 1024 * 1024;
export const MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024;
const BLOCK = 512;

/** A pull reader over a stream of chunks. */
class ByteReader {
  private chunks: Buffer[] = [];
  private buffered = 0;
  private done = false;
  /** Bytes taken from the source so far. */
  total = 0;
  private readonly it: AsyncIterator<Buffer>;
  constructor(
    source: AsyncIterable<Buffer>,
    private readonly maxTotal: number,
  ) {
    this.it = source[Symbol.asyncIterator]();
  }

  private async fill(n: number): Promise<void> {
    while (this.buffered < n && !this.done) {
      const { done, value } = await this.it.next();
      if (done) {
        this.done = true;
        break;
      }
      const buf = Buffer.from(value);
      this.total += buf.length;
      if (this.total > this.maxTotal) throw new Error('tar: archive is over the unpacked size limit');
      this.chunks.push(buf);
      this.buffered += buf.length;
    }
  }

  /** Up to `n` bytes; fewer only at the end of the stream. */
  async read(n: number): Promise<Buffer> {
    await this.fill(n);
    const all = this.chunks.length === 1 ? (this.chunks[0] as Buffer) : Buffer.concat(this.chunks);
    const take = Math.min(n, all.length);
    const out = all.subarray(0, take);
    const rest = all.subarray(take);
    this.chunks = rest.length ? [rest] : [];
    this.buffered = rest.length;
    return out;
  }

  /** Drops `n` bytes; throws if the stream ends first. */
  async skip(n: number): Promise<void> {
    let left = n;
    while (left > 0) {
      const got = await this.read(Math.min(left, 1024 * 1024));
      if (got.length === 0) break;
      left -= got.length;
    }
    if (left > 0) throw new Error('tar: truncated archive');
  }

  close(): void {
    void this.it.return?.();
  }
}

function cstr(buf: Buffer): string {
  const end = buf.indexOf(0);
  return buf.subarray(0, end < 0 ? buf.length : end).toString('utf8');
}

function octal(buf: Buffer, what: string): number {
  const first = buf[0] as number;
  if (first & 0x80) {
    // GNU base-256 number
    let n = first & 0x7f;
    for (let i = 1; i < buf.length; i++) n = n * 256 + (buf[i] as number);
    return n;
  }
  const s = cstr(buf).trim();
  if (s === '') return 0;
  if (!/^[0-7]+$/.test(s)) throw new Error(`tar: bad ${what} field`);
  return Number.parseInt(s, 8);
}

function checksumOk(header: Buffer): boolean {
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : (header[i] as number);
  const field = cstr(header.subarray(148, 156)).trim();
  return /^[0-7]+$/.test(field) && Number.parseInt(field, 8) === sum;
}

/** Reads `path=` from pax records (`<len> <key>=<value>\n`). */
function paxPath(data: Buffer): string | null {
  let pos = 0;
  let path: string | null = null;
  while (pos < data.length) {
    const sp = data.indexOf(0x20, pos);
    if (sp < 0) throw new Error('tar: bad pax record');
    const len = Number(data.subarray(pos, sp).toString('latin1'));
    if (!Number.isInteger(len) || len <= sp - pos + 1 || pos + len > data.length)
      throw new Error('tar: bad pax record');
    const rec = data.subarray(sp + 1, pos + len - 1).toString('utf8');
    const eq = rec.indexOf('=');
    if (eq > 0 && rec.slice(0, eq) === 'path') path = rec.slice(eq + 1);
    pos += len;
  }
  return path;
}

const unsafe = (path: string): boolean =>
  path === '' || path.startsWith('/') || path.includes('\0') || path.split('/').includes('..');

/**
 * Streams a gzipped tar from `body`, calling `onEntry` for each regular file. Directories are ignored; links,
 * devices and the like are skipped and counted, as are entries over `maxEntryBytes` and paths that climb out
 * (`..`, a leading `/`, a NUL). A bad header checksum, a truncated archive or more than `maxTotalBytes`
 * unpacked fails the call.
 */
export async function readTarGz(
  body: ReadableStream<Uint8Array>,
  onEntry: (e: TarEntry) => Promise<void>,
  limits: TarLimits = {},
): Promise<{ files: number; skipped: number }> {
  const maxEntry = limits.maxEntryBytes ?? MAX_ENTRY_BYTES;
  const maxTotal = limits.maxTotalBytes ?? MAX_TOTAL_BYTES;
  const gunzip = createGunzip();
  const source = Readable.fromWeb(body as unknown as WebReadableStream).pipe(gunzip);
  source.on('error', () => {}); // surfaced through the iterator
  const r = new ByteReader(source as AsyncIterable<Buffer>, maxTotal);
  let files = 0;
  let skipped = 0;
  let longName: string | null = null;
  let paxName: string | null = null;
  let zeros = 0;

  const needed = async (n: number): Promise<Buffer> => {
    const b = await r.read(n);
    if (b.length < n) throw new Error('tar: truncated archive');
    return b;
  };
  const pad = (size: number) => (BLOCK - (size % BLOCK)) % BLOCK;

  try {
    for (;;) {
      const header = await r.read(BLOCK);
      if (header.length === 0) break;
      if (header.length < BLOCK) throw new Error('tar: truncated archive');
      if (header.every((b) => b === 0)) {
        if (++zeros === 2) break;
        continue;
      }
      zeros = 0;
      if (!checksumOk(header)) throw new Error('tar: bad header checksum');
      const type = String.fromCharCode(header[156] as number);
      const size = octal(header.subarray(124, 136), 'size');

      if (type === 'x' || type === 'g' || type === 'L') {
        if (size > 1024 * 1024) throw new Error('tar: header record is too large');
        const data = (await needed(size)).subarray(0, size);
        await r.skip(pad(size));
        if (type === 'x') paxName = paxPath(data);
        else if (type === 'L') longName = cstr(data);
        // `g` (global) records are read and dropped: only per-entry paths are used.
        continue;
      }

      const prefix = cstr(header.subarray(345, 500));
      const base = cstr(header.subarray(0, 100));
      const path = paxName ?? longName ?? (prefix ? `${prefix}/${base}` : base);
      paxName = null;
      longName = null;

      const regular = type === '0' || type === '\0';
      if (!regular) {
        if (type !== '5') skipped++;
        await r.skip(size + pad(size));
        continue;
      }
      if (unsafe(path) || size > maxEntry) {
        skipped++;
        await r.skip(size + pad(size));
        continue;
      }

      let text: Promise<string> | null = null;
      let consumed = 0;
      const entry: TarEntry = {
        path,
        size,
        text() {
          text ??= (async () => {
            const data = await needed(size);
            consumed = size;
            return data.toString('utf8');
          })();
          return text;
        },
      };
      files++;
      await onEntry(entry);
      if (text) await text;
      await r.skip(size - consumed + pad(size));
    }
  } finally {
    r.close();
    source.destroy();
  }
  return { files, skipped };
}
