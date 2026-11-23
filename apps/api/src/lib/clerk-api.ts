import { z } from 'zod';

/** Minimal Clerk Backend API client. Plain `fetch`, so tests control every outbound request. */

export const CLERK_API_BASE = 'https://api.clerk.com/v1';

/** A Clerk Backend API call failed. `status` is the HTTP status, or 503 when Clerk is not configured. */
export class ClerkApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ClerkApiError';
  }
}

/** The fields of a Clerk user this app keeps. */
export interface ClerkUserBasics {
  id: string;
  email: string;
  name: string | null;
}

const ClerkUser = z.object({
  id: z.string(),
  email_addresses: z.array(z.object({ id: z.string(), email_address: z.string() })).nullish(),
  primary_email_address_id: z.string().nullish(),
  first_name: z.string().nullish(),
  last_name: z.string().nullish(),
});

async function call(secretKey: string, userId: string, method: 'GET' | 'DELETE'): Promise<Response> {
  if (!secretKey) throw new ClerkApiError(503, 'clerk not configured');
  try {
    return await globalThis.fetch(`${CLERK_API_BASE}/users/${encodeURIComponent(userId)}`, {
      method,
      headers: { Authorization: `Bearer ${secretKey}` },
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    console.warn('clerk request failed', method, userId);
    throw new ClerkApiError(502, 'clerk request failed');
  }
}

/** The Clerk user, or null when Clerk has no such user. */
export async function getClerkUser(secretKey: string, userId: string): Promise<ClerkUserBasics | null> {
  const res = await call(secretKey, userId, 'GET');
  if (res.status === 404) return null;
  if (!res.ok) {
    console.warn('clerk get user failed', userId, res.status);
    throw new ClerkApiError(res.status, 'clerk get user failed');
  }
  const parsed = ClerkUser.safeParse(await res.json().catch(() => null));
  if (!parsed.success) throw new ClerkApiError(502, 'clerk returned an unexpected body');
  const d = parsed.data;
  const emails = d.email_addresses ?? [];
  const primary = emails.find((e) => e.id === d.primary_email_address_id) ?? emails[0];
  const name = [d.first_name, d.last_name].filter(Boolean).join(' ') || null;
  return { id: d.id, email: primary?.email_address ?? '', name };
}

/** Deletes the Clerk user. Idempotent: a user Clerk no longer has counts as deleted. */
export async function deleteClerkUser(secretKey: string, userId: string): Promise<void> {
  const res = await call(secretKey, userId, 'DELETE');
  if (res.ok || res.status === 404) return;
  console.warn('clerk delete user failed', userId, res.status);
  throw new ClerkApiError(res.status, 'clerk delete user failed');
}
