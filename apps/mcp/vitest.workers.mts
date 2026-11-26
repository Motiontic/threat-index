import { workerProject } from '../../test/workers-project.mts';

// Dummy secrets, never real ones.
export const MCP_BINDINGS = {
  MCP_HMAC_SECRET: 'test-mcp-hmac-secret',
  MCP_HMAC_SECRET_NEXT: 'test-mcp-hmac-secret-next',
};

/**
 * ti-mcp's Workers project: no databases, and an in-test handler in place of the `API` service binding
 * (ti-api-staging does not exist in the test runtime, and these tests don't need ti-api). The handler
 * echoes the request it was given, so a test can check what `callApi` built and verify the assertion itself.
 */
export default workerProject(
  import.meta.dirname,
  'mcp',
  'mcp',
  ['test/**/*.workers.test.ts'],
  {},
  MCP_BINDINGS,
  {
    serviceBindings: {
      API: async (request: Request) => {
        const headers: Record<string, string> = {};
        for (const [k, v] of request.headers) headers[k] = v;
        return Response.json({
          method: request.method,
          url: request.url,
          headers,
          body: await request.text(),
        });
      },
    },
  },
);
