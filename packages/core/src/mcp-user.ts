/**
 * The signed identity `ti-mcp` sends to `ti-api`. `ti-mcp` checks the user's OAuth token itself and never
 * forwards it: it sends a short-lived HMAC assertion bound to this one request (method, path and query,
 * body hash, request id), so a captured assertion can't be replayed against anything else.
 * Web Crypto only.
 */
import { constantTimeEqual, hmac } from './sign';

export const MCP_HEADERS = {
  sub: 'x-ti-mcp-sub',
  scopes: 'x-ti-mcp-scopes',
  client: 'x-ti-mcp-client',
  ts: 'x-ti-mcp-ts',
  sig: 'x-ti-mcp-sig',
} as const;
export const MCP_SKEW_SECONDS = 60;
export const MCP_SCOPES = ['mti:read', 'mti:watch'] as const;

export interface McpIdentity {
  sub: string;
  scopes: string[];
  clientId: string;
}
export interface McpRequestBinding {
  requestId: string;
  method: string;
  pathWithQuery: string;
  body: ArrayBuffer | null;
}

const SUB = /^user_[A-Za-z0-9]{10,64}$/;
const CLIENT_ID = /^[\x20-\x7e]{1,512}$/;
const TS = /^\d{1,15}$/;

async function sha256Hex(body: ArrayBuffer | null): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', body ?? new ArrayBuffer(0));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function message(id: McpIdentity, req: McpRequestBinding, ts: number | string): Promise<string> {
  return `mcp-assertion/v1\naud=ti-api\n${[
    id.sub,
    [...id.scopes].sort().join(' '),
    id.clientId,
    req.requestId,
    req.method.toUpperCase(),
    req.pathWithQuery,
    await sha256Hex(req.body),
    String(ts),
  ].join('\n')}`;
}

/** hex(HMAC-SHA256(secret, "mcp-assertion/v1\naud=ti-api\n" + [sub, sortedScopes, clientId, requestId, METHOD, pathWithQuery, sha256hex(body), ts].join("\n"))). */
export async function signMcpAssertion(
  secret: string,
  id: McpIdentity,
  req: McpRequestBinding,
  ts: number,
): Promise<Record<string, string>> {
  if (!secret) throw new Error('signMcpAssertion: empty secret');
  return {
    [MCP_HEADERS.sub]: id.sub,
    [MCP_HEADERS.scopes]: [...id.scopes].sort().join(' '),
    [MCP_HEADERS.client]: id.clientId,
    [MCP_HEADERS.ts]: String(ts),
    [MCP_HEADERS.sig]: await hmac(secret, await message(id, req, ts)),
  };
}

/**
 * Tries each secret (current, then next, for rotation). Fails closed: missing header, bad format
 * (sub /^user_[A-Za-z0-9]{10,64}$/, clientId 1 to 512 printable characters, scopes ⊆ MCP_SCOPES),
 * skew over 60 s, or a signature that matches no secret.
 */
export async function verifyMcpAssertion(
  secrets: (string | undefined)[],
  headers: Headers,
  req: McpRequestBinding,
  now: Date = new Date(),
): Promise<McpIdentity | null> {
  const sub = headers.get(MCP_HEADERS.sub);
  const scopesRaw = headers.get(MCP_HEADERS.scopes);
  const clientId = headers.get(MCP_HEADERS.client);
  const tsRaw = headers.get(MCP_HEADERS.ts);
  const sig = headers.get(MCP_HEADERS.sig);
  if (sub === null || scopesRaw === null || clientId === null || tsRaw === null || !sig) return null;
  if (!SUB.test(sub) || !CLIENT_ID.test(clientId) || !TS.test(tsRaw)) return null;
  const scopes = scopesRaw === '' ? [] : scopesRaw.split(' ');
  const known: readonly string[] = MCP_SCOPES;
  if (scopes.some((s) => !known.includes(s))) return null;
  const ts = Number(tsRaw);
  if (Math.abs(now.getTime() / 1000 - ts) > MCP_SKEW_SECONDS) return null;
  const id: McpIdentity = { sub, scopes: [...scopes].sort(), clientId };
  const msg = await message(id, req, tsRaw);
  let ok = false;
  for (const secret of secrets) {
    if (!secret) continue;
    // Check every secret (no early exit) so timing doesn't reveal which one matched.
    if (constantTimeEqual(await hmac(secret, msg), sig)) ok = true;
  }
  return ok ? id : null;
}
