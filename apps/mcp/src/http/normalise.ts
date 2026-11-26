import { APP_CODES, FIXED_MESSAGES } from './errors';

const INPUT_MSG =
  "The arguments do not match this tool's input schema. Check required fields, types and length limits.";

function inReserved(code: number): boolean {
  return code >= -32768 && code <= -32000;
}

function fixError(err: Record<string, unknown>, status: number, requestId: string): void {
  let code = typeof err.code === 'number' ? err.code : -32603;
  const old = err.data as Record<string, unknown> | undefined;
  const isOurs = Object.values(APP_CODES).includes(code as never);
  if (!isOurs && inReserved(code) && !(code in FIXED_MESSAGES)) {
    code =
      status === 415
        ? APP_CODES.unsupported_media_type
        : status === 413
          ? APP_CODES.body_too_large
          : status === 406
            ? APP_CODES.not_acceptable
            : APP_CODES.bad_request;
  }
  err.code = code;
  err.message = FIXED_MESSAGES[code] ?? 'Error';
  const data: Record<string, unknown> = { requestId };
  if (code === -32022 && Array.isArray(old?.supported))
    data.supported = old.supported.filter((v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v));
  if (code === -32021 && old?.requiredCapabilities !== undefined)
    data.requiredCapabilities = old.requiredCapabilities;
  if (code === -32602 && typeof old?.field === 'string' && old.field === 'cursor') data.field = 'cursor';
  err.data = data;
}

/** Rewrites an `application/json` answer so no SDK text, header value or reserved-range code gets out. */
export interface SeenInfo {
  code?: number;
  toolError?: boolean;
}

export async function normaliseResponse(
  res: Response,
  requestId: string,
  seen: SeenInfo = {},
): Promise<Response> {
  if (!res.headers.get('content-type')?.toLowerCase().startsWith('application/json')) return res;
  const text = await res.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return new Response(text, { status: res.status, headers: res.headers });
  }
  const fix = (m: unknown) => {
    if (!m || typeof m !== 'object') return;
    const o = m as Record<string, unknown>;
    if (o.error && typeof o.error === 'object') {
      fixError(o.error as Record<string, unknown>, res.status, requestId);
      seen.code = (o.error as { code: number }).code;
    }
    const r = o.result as { isError?: unknown; content?: { type?: string; text?: unknown }[] } | undefined;
    if (r?.isError === true) seen.toolError = true;
    if (r?.isError === true && Array.isArray(r.content)) {
      const first = r.content[0];
      if (typeof first?.text === 'string') {
        if (first.text.startsWith('Input validation error:'))
          first.text = `${INPUT_MSG} Request ID: ${requestId}.`;
        else if (first.text.startsWith('Output validation error:'))
          first.text = `Something went wrong on the MTI side. Request ID: ${requestId}.`;
      }
    }
  };
  if (Array.isArray(body)) body.forEach(fix);
  else fix(body);
  const headers = new Headers(res.headers);
  headers.delete('content-length');
  return new Response(JSON.stringify(body), { status: res.status, statusText: res.statusText, headers });
}
