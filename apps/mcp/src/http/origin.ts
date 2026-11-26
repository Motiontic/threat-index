export function allowedOrigins(raw: string | undefined): Set<string> {
  const out = new Set<string>();
  for (const item of (raw ?? '').split(',')) {
    const t = item.trim();
    if (!t) continue;
    try {
      const u = new URL(t);
      if (u.origin !== 'null') out.add(u.origin);
    } catch {
      // bad entries are dropped
    }
  }
  return out;
}

export function checkOrigin(
  request: Request,
  allowed: Set<string>,
): { ok: true; origin: string | null } | { ok: false } {
  const raw = request.headers.get('origin');
  if (raw === null) return { ok: true, origin: null };
  let origin: string;
  try {
    origin = new URL(raw).origin;
  } catch {
    return { ok: false };
  }
  // Exact match: scheme, host and port. The raw value must also be the canonical origin.
  return origin === raw && allowed.has(origin) ? { ok: true, origin } : { ok: false };
}

export function corsHeaders(origin: string): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin,
    Vary: 'Origin',
    'Access-Control-Expose-Headers': 'WWW-Authenticate, Retry-After, x-request-id',
  };
}

export function preflight(origin: string, methods: string): Response {
  return new Response(null, {
    status: 204,
    headers: {
      ...corsHeaders(origin),
      'Access-Control-Allow-Methods': methods,
      'Access-Control-Allow-Headers':
        'authorization, content-type, accept, mcp-protocol-version, mcp-method, mcp-name, traceparent, tracestate',
      'Access-Control-Max-Age': '600',
    },
  });
}
