import { getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/server';
import { json } from '../http/respond';
import type { AuthReason } from './verify';

export function metadataUrl(resource: string): string {
  return getOAuthProtectedResourceMetadataUrl(new URL(resource));
}

export type AuthFailure =
  | { kind: 'none' }
  | { kind: 'malformed' }
  | { kind: 'reason'; reason: AuthReason }
  | { kind: 'scope' }
  | { kind: 'unavailable' };

/** The 401, 403 and 503 answers sent before the SDK runs. Never a 200. */
export function challenge(f: AuthFailure, resource: string, requestId: string): Response {
  const url = metadataUrl(resource);
  switch (f.kind) {
    case 'none':
      return json({ error: 'unauthorized', requestId }, 401, {
        'WWW-Authenticate': `Bearer resource_metadata="${url}", scope="mti:read"`,
      });
    case 'malformed':
    case 'reason':
      return json({ error: 'invalid_token', requestId }, 401, {
        'WWW-Authenticate': `Bearer error="invalid_token", resource_metadata="${url}", scope="mti:read"`,
      });
    case 'scope':
      return json({ error: 'insufficient_scope', requestId }, 403, {
        'WWW-Authenticate': `Bearer error="insufficient_scope", scope="mti:read", resource_metadata="${url}"`,
      });
    case 'unavailable':
      return json({ error: 'temporarily_unavailable', requestId }, 503, { 'Retry-After': '30' });
  }
}
