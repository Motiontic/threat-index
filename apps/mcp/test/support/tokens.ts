import { vi } from 'vitest';
import { resetJwksCacheForTests } from '../../src/auth/jwks';

export const ISS = 'https://clerk.mti.test';
export const RES = 'https://mti.test/mcp';
export const JWKS_URL = `${ISS}/.well-known/jwks.json`;
export const SUB = 'user_2abcdefghijk';

const enc = new TextEncoder();
export const b64u = (b: ArrayBuffer | Uint8Array | string): string => {
  const bytes = typeof b === 'string' ? enc.encode(b) : new Uint8Array(b);
  let s = '';
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export interface TestKey {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JsonWebKey;
}
export async function makeKey(kid = 'k1', bits = 2048): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const publicJwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
  return { kid, privateKey: pair.privateKey, publicJwk };
}

export function goodPayload(over: Record<string, unknown> = {}, now = Math.floor(Date.now() / 1000)) {
  return {
    iss: ISS,
    aud: RES,
    sub: SUB,
    client_id: 'client-abc',
    scope: 'mti:read',
    iat: now - 10,
    exp: now + 3600,
    ...over,
  };
}

/** Signs a JWT. Pass `header`/`payload` overrides; a key set to `undefined` is removed. */
export async function signJwt(
  key: TestKey,
  payload: Record<string, unknown> = goodPayload(),
  header: Record<string, unknown> = {},
  opts: { sigBytes?: Uint8Array } = {},
): Promise<string> {
  const h = { alg: 'RS256', typ: 'at+jwt', kid: key.kid, ...header };
  for (const o of [h, payload]) for (const k of Object.keys(o)) if (o[k] === undefined) delete o[k];
  const signing = `${b64u(JSON.stringify(h))}.${b64u(JSON.stringify(payload))}`;
  const sig =
    opts.sigBytes ?? new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key.privateKey, enc.encode(signing)));
  return `${signing}.${b64u(sig)}`;
}

export type JwksMode = 'ok' | '500' | 'timeout' | 'redirect' | 'badjson' | 'weak';
export interface JwksSpy {
  calls: string[];
  mode: JwksMode;
  keys: TestKey[];
  restore(): void;
}

/** Spies on `globalThis.fetch`: serves the fake JWKS for the issuer's URL and records every other URL. */
export function mockJwks(keys: TestKey[], mode: JwksMode = 'ok'): JwksSpy {
  resetJwksCacheForTests();
  const real = globalThis.fetch;
  const spy: JwksSpy = { calls: [], mode, keys, restore: () => {} };
  const mock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    spy.calls.push(url);
    if (url !== JWKS_URL) throw new Error(`unexpected fetch ${url}`);
    expectInit(init);
    switch (spy.mode) {
      case '500':
        return new Response('nope', { status: 500 });
      case 'timeout':
        throw new DOMException('timed out', 'TimeoutError');
      case 'redirect':
        throw new TypeError('redirect mode is set to error');
      case 'badjson':
        return new Response('{not json', { status: 200 });
      case 'weak': {
        const weak = await makeKey('weak', 1024);
        return Response.json({ keys: [{ ...weak.publicJwk, kid: 'weak', use: 'sig', alg: 'RS256' }] });
      }
      default:
        return Response.json({
          keys: spy.keys.map((k) => ({ ...k.publicJwk, kid: k.kid, use: 'sig', alg: 'RS256', ext: undefined, key_ops: undefined })),
        });
    }
  });
  spy.restore = () => {
    mock.mockRestore();
    globalThis.fetch = real;
  };
  return spy;
}

function expectInit(init?: RequestInit) {
  if (init?.redirect !== 'error') throw new Error('JWKS fetch must use redirect: "error"');
}
