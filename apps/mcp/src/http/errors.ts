export const APP_CODES = {
  unsupported_media_type: -31002,
  body_too_large: -31003,
  not_acceptable: -31004,
  origin_not_allowed: -31005,
  rate_limited: -31006,
  headers_too_large: -31007,
  json_too_deep: -31008,
  unavailable: -31009,
  bad_request: -31010,
} as const;

export const FIXED_MESSAGES: Record<number, string> = {
  [-32700]: 'Parse error',
  [-32600]: 'Invalid request',
  [-32601]: 'Method not found',
  [-32602]: 'Invalid params',
  [-32603]: 'Internal error',
  [-32020]: 'Request headers do not match the body',
  [-32021]: 'Missing required client capability',
  [-32022]: 'Unsupported protocol version',
  [APP_CODES.unsupported_media_type]: 'Content-Type must be application/json',
  [APP_CODES.body_too_large]: 'Request body is too large',
  [APP_CODES.not_acceptable]: 'Not acceptable',
  [APP_CODES.origin_not_allowed]: 'Origin not allowed',
  [APP_CODES.rate_limited]: 'Too many requests',
  [APP_CODES.headers_too_large]: 'Request headers are too large',
  [APP_CODES.json_too_deep]: 'JSON is nested too deeply',
  [APP_CODES.unavailable]: 'Service temporarily unavailable',
  [APP_CODES.bad_request]: 'Bad request',
};

/** A JSON-RPC error answer with a fixed message and `data.requestId`. `finish` adds the headers. */
export function rpcError(
  status: number,
  code: number,
  requestId: string,
  id: string | number | null = null,
  extra: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): Response {
  const body = {
    jsonrpc: '2.0',
    id,
    error: { code, message: FIXED_MESSAGES[code] ?? 'Error', data: { requestId, ...extra } },
  };
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}
