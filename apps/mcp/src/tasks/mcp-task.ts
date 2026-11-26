import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../env';
import { NotImplementedError } from '../errors';

/** Long-running MCP Tasks. A skeleton: the class exists so the Durable Object binding and migration are in place. */
export class McpTask extends DurableObject<Env> {
  override async fetch(_request: Request): Promise<Response> {
    throw new NotImplementedError('McpTask.fetch');
  }

  override async alarm(): Promise<void> {
    throw new NotImplementedError('McpTask.alarm');
  }
}
