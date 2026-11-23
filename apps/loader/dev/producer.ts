// Local-only helper for the loop sandbox proof. NEVER DEPLOYED: scripts/deploy.mjs deploys only
// apps/<app>/wrangler.jsonc, and this Worker's config is apps/loader/dev/wrangler.jsonc.
// POST /send puts its JSON body on the ti-load queue (binding LOAD) so a local loader can consume it.
interface Env {
  LOAD: Queue<unknown>;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/send')
      return new Response('not found', { status: 404 });
    await env.LOAD.send(await request.json());
    return new Response('queued\n');
  },
} satisfies ExportedHandler<Env>;
