import { createHash, randomBytes } from 'node:crypto';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function timePart(timeMs: number): string {
  let t = Math.floor(timeMs);
  let out = '';
  for (let i = 0; i < 10; i++) {
    out = CROCKFORD[t % 32] + out;
    t = Math.floor(t / 32);
  }
  return out;
}

/** 80 bits as 16 Crockford base32 characters (5 bits each). */
function base32(bytes: Uint8Array): string {
  let bits = 0n;
  for (const b of bytes.subarray(0, 10)) bits = (bits << 8n) | BigInt(b);
  let out = '';
  for (let i = 0; i < 16; i++) {
    out = CROCKFORD[Number(bits & 31n)] + out;
    bits >>= 5n;
  }
  return out;
}

/** A ULID: 10 characters of millisecond time, then 80 random bits. Sortable by time. */
export function newUlid(now: number = Date.now()): string {
  return timePart(now) + base32(randomBytes(10));
}

/** Same shape, but the random part is the first 80 bits of SHA-256(seed): the same inputs give the same id. */
export function deterministicUlid(timeMs: number, seed: string): string {
  return timePart(timeMs) + base32(createHash('sha256').update(seed).digest());
}
