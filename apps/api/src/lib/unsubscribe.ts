import { PRODUCT_SHORT } from '@ti/core/brand';
import type { UnsubscribePayload } from '@ti/core/unsubscribe';

/** Applies one unsubscribe, always scoped to the token's user. Idempotent; missing rows are not an error. */
export async function applyUnsubscribe(db: D1Database, p: UnsubscribePayload): Promise<void> {
  switch (p.scope) {
    case 'all':
      await db
        .prepare("UPDATE users SET alert_instant = 0, digest = 'off' WHERE id = ?1")
        .bind(p.userId)
        .run();
      return;
    case 'digest':
      await db.prepare("UPDATE users SET digest = 'off' WHERE id = ?1").bind(p.userId).run();
      return;
    case 'watch':
      await db
        .prepare('UPDATE watch SET alerts_on = 0 WHERE user_id = ?1 AND entry_key = ?2')
        .bind(p.userId, p.item ?? '')
        .run();
      return;
    case 'search':
      await db
        .prepare('UPDATE saved_searches SET alerts_on = 0 WHERE user_id = ?1 AND id = ?2')
        .bind(p.userId, p.item ?? '')
        .run();
      return;
  }
}

const escapeHtml = (s: string): string =>
  s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

function what(p: UnsubscribePayload): string {
  switch (p.scope) {
    case 'all':
      return `all ${PRODUCT_SHORT} alert email`;
    case 'digest':
      return 'digest email';
    case 'watch':
      return `alerts for ${escapeHtml(p.item ?? '')}`;
    case 'search':
      return 'alerts for this saved search';
  }
}

/** A small self-contained page: inline CSS, no scripts, no external resources. */
export function renderPage(
  kind: 'confirm' | 'done' | 'invalid',
  p?: UnsubscribePayload,
  token?: string,
): string {
  let title: string;
  let body: string;
  if (kind === 'invalid' || !p) {
    title = 'Link not valid';
    body = '<p>This unsubscribe link is not valid. You can change your email settings from your account.</p>';
  } else if (kind === 'confirm') {
    title = 'Unsubscribe';
    body = `<p>Stop receiving ${what(p)}?</p>
<form method="post" action="/unsubscribe?t=${escapeHtml(token ?? '')}">
<input type="hidden" name="List-Unsubscribe" value="One-Click">
<button type="submit">Unsubscribe</button>
</form>`;
  } else {
    title = 'Unsubscribed';
    body = `<p>You will no longer receive ${what(p)}. You can turn alerts back on in your account settings.</p>`;
  }
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · ${PRODUCT_SHORT}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#111}button{font:inherit;padding:.5rem 1rem;cursor:pointer}</style>
</head>
<body>
<h1>${title}</h1>
${body}
</body>
</html>
`;
}
