import { cloudflare } from '@cloudflare/vite-plugin';
import { reactRouter } from '@react-router/dev/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [cloudflare({ viteEnvironment: { name: 'ssr' } }), reactRouter()],
  build: {
    // The CSP has no `data:` source, so no asset may become a data: URL.
    assetsInlineLimit: 0,
  },
});
