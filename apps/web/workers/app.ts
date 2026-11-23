import { env } from 'cloudflare:workers';
import { createRequestHandler } from 'react-router';
import { SAMPLE_DATA } from '../app/data/data.server';
import { secureRedirect, shouldNoindex } from '../app/lib/security.server';

const requestHandler = createRequestHandler(
  () => import('virtual:react-router/server-build'),
  import.meta.env.MODE,
);

export default {
  async fetch(request) {
    const response = await requestHandler(request);
    // Loader redirects never reach `handleRequest`; give them the document headers here.
    return secureRedirect(response, {
      dev: import.meta.env.DEV,
      noindex: shouldNoindex(SAMPLE_DATA, env.TI_ENV),
    });
  },
} satisfies ExportedHandler<Env>;
