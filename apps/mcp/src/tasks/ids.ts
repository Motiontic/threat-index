const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const TASK_ID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

/** 128 random bits as 26 Crockford base32 characters (the first carries 3 bits, so it is 0 to 7). */
export function newTaskId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  for (let i = 0; i < 26; i++) {
    out = CROCKFORD[Number(n & 31n)] + out;
    n >>= 5n;
  }
  return out;
}
