import { logEvent } from '@ti/core/log';

export type Outcome = 'ok' | 'tool_error' | 'rpc_error' | 'auth' | 'limited' | 'rejected';
export interface RequestLog {
  requestId: string;
  route: 'mcp' | 'card' | 'metadata';
  era?: 'modern' | 'legacy';
  method?: string;
  tool?: string;
  status: number;
  outcome: Outcome;
  code?: number | string;
  authReason?: string;
  nIn?: number;
  nOut?: number;
  ecosystems?: string;
  ms: number;
  sub?: string;
  clientId?: string;
  traceparent?: string;
  toolsHash?: string;
}

/** One `mcp_request` line per HTTP request. Never arguments, results, tokens, IPs or SDK messages. */
export function logRequest(entry: RequestLog): void {
  const level = entry.outcome === 'ok' ? 'info' : 'warn';
  logEvent(level, 'mcp_request', { ...entry });
}
