// A `Fetcher` that records each Request and answers from a map of path (with query) → status and body.
export interface FakeRoute {
  status?: number;
  body?: unknown;
  /** Raw text instead of JSON. */
  text?: string;
  headers?: Record<string, string>;
  throws?: Error;
}

export function fakeApi(routes: Record<string, FakeRoute>) {
  const requests: Request[] = [];
  const api: Pick<Fetcher, 'fetch'> = {
    async fetch(input: RequestInfo | URL, init?: RequestInit) {
      const req = new Request(input as RequestInfo, init);
      requests.push(req);
      const url = new URL(req.url);
      const route = routes[url.pathname + url.search] ?? routes[url.pathname];
      if (!route) return new Response('{"error":"Not found"}', { status: 404 });
      if (route.throws) throw route.throws;
      const body = route.text ?? JSON.stringify(route.body ?? {});
      return new Response(body, {
        status: route.status ?? 200,
        headers: { 'Content-Type': 'application/json', ...route.headers },
      });
    },
  };
  return { api, requests };
}

export const CREDIT = { sourceId: 'cisa-kev', name: 'CISA KEV', text: 'Source: CISA KEV' };
export const PREVIEW = {
  key: 'CVE-2025-1',
  kind: 'cve',
  title: 'T',
  summary: 'S',
  aliases: ['GHSA-x'],
  exploited: true,
  credits: [CREDIT],
};
