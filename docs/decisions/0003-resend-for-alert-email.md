# 0003. Resend for alert email

- Status: accepted
- Date: 2026-11-22

## Context

Users get email alerts about watched entries. Cloudflare Email Routing can only send to addresses verified on our own account. Cloudflare Email Service can send to anyone, but it needs the $5 Workers plan and is in public beta. Clerk sends its own sign-in codes.

## Decision

Use **Resend**. Its free plan gives 3,000 emails a month and 100 a day. We call its HTTP API from a Worker and send up to 100 emails per batch call.

To stay within 100 a day:

- **daily digest by default;**
- **weekly digests** go out on each user's sign-up weekday;
- **"as it happens"** is bundled into one email per 3-hour run;
- **a daily cap of 95**, with leftovers rolled to the next run.

Every email carries one-click unsubscribe headers (RFC 8058). Bounces and complaints, received through Resend webhooks, suppress the address.

## Consequences

- About 100 daily-digest users, or about 700 weekly users, fit on the free plan.
- To grow: Resend Pro, or Cloudflare Email Service on the $5 Workers plan.
