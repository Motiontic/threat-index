import { requestIdFrom } from '@ti/core/log';
import { SUPPORTED_PROTOCOL_VERSIONS } from '@modelcontextprotocol/server';
import { SERVER_INFO, siteOrigin } from './config';
import type { Env } from './env';
import { finish, json } from './http/respond';
import { logRequest } from './log';
import { limitAnon } from './rate-limit';

export const SERVER_CARD_SCHEMA = 'https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json';

export interface ServerCard {
  $schema: string;
  name: string;
  version: string;
  title: string;
  description: string;
  websiteUrl: string;
  repository: { url: string; source: string; subfolder: string };
  remotes: { type: 'streamable-http'; url: string; supportedProtocolVersions: string[] }[];
}

export function serverCard(env: Env): ServerCard {
  return {
    $schema: SERVER_CARD_SCHEMA,
    name: 'com.motiontic/mti',
    version: SERVER_INFO.version,
    title: SERVER_INFO.title,
    description: 'Known vulnerabilities, malicious packages, exploitation signals, breaches and AI incidents.',
    websiteUrl: siteOrigin(env),
    repository: { url: 'https://github.com/Motiontic/threat-index', source: 'github', subfolder: 'apps/mcp' },
    remotes: [
      { type: 'streamable-http', url: env.MCP_RESOURCE_URL, supportedProtocolVersions: [...SUPPORTED_PROTOCOL_VERSIONS] },
    ],
  };
}

const CORS = { 'Access-Control-Allow-Origin': '*' };

function matches(header: string | null, etag: string): boolean {
  if (!header) return false;
  return header.split(',').some((t) => {
    const v = t.trim();
    return v === '*' || v.replace(/^W\//, '') === etag;
  });
}

export async function handleCard(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
  const started = Date.now();
  const requestId = requestIdFrom(request.headers.get('x-request-id'));
  const done = (res: Response, outcome: 'ok' | 'limited' | 'rejected') => {
    logRequest({ requestId, route: 'card', status: res.status, outcome, ms: Date.now() - started });
    return finish(res, { requestId });
  };
  if (await limitAnon(env, request))
    return done(json({ error: 'rate_limited', requestId }, 429, { ...CORS, 'Retry-After': '60' }), 'limited');
  if (request.method === 'OPTIONS')
    return done(
      new Response(null, {
        status: 204,
        headers: { ...CORS, 'Access-Control-Allow-Methods': 'GET, HEAD', 'Access-Control-Allow-Headers': 'Content-Type, If-None-Match' },
      }),
      'ok',
    );
  if (request.method !== 'GET' && request.method !== 'HEAD')
    return done(json({ error: 'method_not_allowed', requestId }, 405, { Allow: 'GET, HEAD, OPTIONS' }), 'rejected');
  const body = JSON.stringify(serverCard(env));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
  const etag = `"${[...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32)}"`;
  const headers = {
    'Content-Type': 'application/mcp-server-card+json',
    ...CORS,
    'Access-Control-Expose-Headers': 'ETag',
    'Cache-Control': 'public, max-age=3600',
    ETag: etag,
  };
  if (matches(request.headers.get('if-none-match'), etag)) return done(new Response(null, { status: 304, headers }), 'ok');
  return done(new Response(request.method === 'HEAD' ? null : body, { status: 200, headers }), 'ok');
}
