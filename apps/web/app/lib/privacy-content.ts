// The words of the privacy page, as data. Each statement carries `refs`: the file and line that proves it
// (paths from the repo root). A test checks that every section has statements, every statement has refs, and
// every ref points at a real line. Refs are never shown on the page. If the code and a statement disagree,
// the statement changes. `[[OWNER: …]]` marks a decision only the owner can make; see privacy.ts.

export const LAST_UPDATED = '2026-11-27';

export interface Statement {
  text: string;
  /** `path:line` or `path:from-to`, from the repo root. */
  refs: string[];
}

export interface PrivacySection {
  id: string;
  title: string;
  statements: Statement[];
}

export const PRIVACY_SECTIONS: PrivacySection[] = [
  {
    id: 'who',
    title: 'Who runs MTI and how to reach us',
    statements: [
      {
        text: 'MTI, the Motiontic Threat Index, is run by [[OWNER: legal name of the operator]].',
        refs: ['owner-decision'],
      },
      {
        text: 'Postal address: [[OWNER: postal or contact address]]. Privacy questions and requests: [[OWNER: privacy contact email; TI_CONTACT_EMAIL is the likely address, please confirm]].',
        refs: ['apps/collector/wrangler.jsonc:49', 'owner-decision'],
      },
      {
        text: 'This page and the service are governed by the law of [[OWNER: governing law]]. You must be at least [[OWNER: minimum age]] years old to make an account.',
        refs: ['owner-decision'],
      },
    ],
  },
  {
    id: 'collect',
    title: 'What we collect, and why',
    statements: [
      {
        text: 'Reading the public site needs no account. The records themselves (vulnerabilities, breach notices, incidents, techniques) are public data from the sources listed on the Sources page, not data about you.',
        refs: ['apps/web/app/routes.ts:4-17'],
      },
      {
        text: 'When you make an account we keep your Clerk user ID, your verified email address, your name and the date you joined, so we can sign you in and send the alerts you ask for. Your display name, alert settings (instant alerts, daily or weekly digest, digest weekday, alert triggers) and plan are stored with them.',
        refs: [
          'packages/db/migrations/users/0001_init.sql:2-10',
          'packages/db/migrations/users/0002_account_settings.sql:4-6',
          'apps/api/src/routes/webhooks-clerk.ts:41-52',
        ],
      },
      {
        text: 'We keep what you save: the records and packages you watch (and whether alerts are on for each) and your saved searches with their label, query and settings.',
        refs: [
          'packages/db/migrations/users/0001_init.sql:12-22',
          'packages/db/migrations/users/0004_mcp.sql:1-6',
          'packages/db/migrations/users/0002_account_settings.sql:9-10',
        ],
      },
      {
        text: 'To send alerts we keep a short queue of changes waiting to be emailed to you, a record of which changes we have already emailed, a per-day count of instant emails, and one row for each email attempt (a hashed key, the kind, the number of changes, the status and the mail provider’s message ID). The send rows hold no address and no user ID.',
        refs: [
          'packages/db/migrations/users/0001_init.sql:24-34',
          'packages/db/migrations/users/0003_notify.sql:1-10',
          'packages/db/migrations/users/0005_watch_events.sql:16-19',
        ],
      },
      {
        text: 'For the package checks in the MCP server we keep a per-day count of how many packages you checked and how many calls you made, to apply fair-use limits.',
        refs: ['packages/db/migrations/users/0004_mcp.sql:8-13'],
      },
      {
        text: 'When your watchlist is changed through an AI client, we keep a record of the change (what was added, removed or switched, when, and the host name of the AI client if it gave one as a web address) for up to 30 days, so we can email you that it happened.',
        refs: [
          'packages/db/migrations/users/0005_watch_events.sql:3-14',
          'apps/api/src/lib/watch-events.ts:8-16',
          'apps/notify/src/limits.ts:41',
        ],
      },
      {
        text: 'When you start a deep query, we keep a job row (an ID, the kind, a status, the sandbox ID, times and any error code) and the query itself (the template and its parameters) plus its result in object storage under that job. The job row names its owner only by a keyed hash, never by your user ID.',
        refs: [
          'packages/db/migrations/control/0001_init.sql:20-23',
          'apps/api/src/lib/deep-query.ts:46-49',
          'apps/api/src/routes/deep-query.ts:196-199',
        ],
      },
      {
        text: 'We keep a few operational records that hold no personal data: webhook delivery IDs (so an event is handled once) and a daily count of emails sent.',
        refs: [
          'packages/db/migrations/users/0001_init.sql:34-37',
          'apps/api/src/routes/webhooks-clerk.ts:17-31',
        ],
      },
      {
        text: 'Our servers write request logs (see “How long we keep each thing”). The account database has no place to store an IP address. To limit abuse, an IP address (for IPv6, its first four groups) is used as a short-lived rate-limit key in Cloudflare’s rate limiter.',
        refs: ['packages/core/src/edge.ts:44-56', 'apps/web/workers/app.ts:25'],
      },
    ],
  },
  {
    id: 'not-collected',
    title: 'What we don’t collect',
    statements: [
      {
        text: 'MTI never asks for your source code, files, lockfiles or secrets. The package-check tool takes package names and versions (an ecosystem, a name and a version, or a package URL) and nothing else about your project. The tool that would read a software bill of materials is switched off.',
        refs: [
          'apps/mcp/src/tools/check-format.ts:21-30',
          'apps/mcp/src/tools/mti_check_sbom.ts:1-2',
          'apps/mcp/src/tools/mti_check_packages.ts:21',
        ],
      },
      {
        text: 'The other MCP tools take search words, record IDs, watchlist entries and the fixed parameters of a deep-query template, each with a length limit. They have no field for files or credentials.',
        refs: ['apps/mcp/src/tools/mti_search.ts:26', 'apps/mcp/src/tools/mti_deep_query.ts:23-38'],
      },
      {
        text: 'We do not use analytics, advertising or error-tracking services, and we do not load fonts, scripts or images from other sites on this page. Fonts are served from our own domain, and the browser is only allowed to load from our own domain (plus Clerk’s sign-in host and Cloudflare’s bot check, which load only when sign-in is on).',
        refs: [
          'apps/web/app/root.tsx:4-5',
          'apps/web/app/lib/security.server.ts:36-49',
          'apps/web/app/lib/auth.tsx:183',
        ],
      },
    ],
  },
  {
    id: 'retention',
    title: 'How long we keep each thing',
    statements: [
      {
        text: 'Your account row, watchlist, watched packages, saved searches and daily package-check counts are kept until you delete your account.',
        refs: ['apps/api/src/lib/delete-user.ts:15-27', 'apps/notify/src/consume.ts:327-342'],
      },
      {
        text: 'Emails waiting to go out are dropped after 14 days. Records of sent alerts, email attempt rows and daily email counts are deleted after 30 days. Instant-email counts are deleted after 2 days. Watchlist change records from AI clients are deleted after 30 days. A daily job does this.',
        refs: [
          'apps/notify/src/limits.ts:10-11',
          'apps/notify/src/limits.ts:40-41',
          'apps/notify/src/consume.ts:327-342',
        ],
      },
      {
        text: 'MCP Tasks (long package checks and deep queries run through an AI client) are stored per user and deleted 90 minutes after creation for package checks and 70 minutes for deep queries, at the latest.',
        refs: ['apps/mcp/src/tasks/mcp-task.ts:28-34', 'apps/mcp/src/tasks/client.ts:9'],
      },
      {
        text: 'Deep-query job rows and the query and result files in object storage have no automatic deletion date today, and account deletion does not remove them. The job row identifies you only by a keyed hash. We will set a deletion period and update this page when we do.',
        refs: ['apps/api/src/lib/delete-user.ts:15-27', 'apps/api/src/lib/deep-query.ts:46-49'],
      },
      {
        text: 'Delivery IDs for webhooks are kept without an expiry; they hold no personal data.',
        refs: ['packages/db/migrations/users/0001_init.sql:37', 'apps/notify/src/consume.ts:327-342'],
      },
      {
        text: 'Request logs go to Cloudflare Workers Logs and are kept for the period that service keeps them. Each web, API, MCP and notify request is logged as a line with a request ID, method, route, status and time. The API adds your Clerk user ID to that line when you are signed in. The MCP server never logs your user ID or the AI client’s ID, tool arguments, results, tokens or IP addresses. Email addresses are removed from log fields before they are written. Some error lines (a failed Clerk call, for example) name the Clerk user ID.',
        refs: [
          'apps/api/src/lib/request-context.ts:25-32',
          'apps/web/workers/app.ts:71-77',
          'apps/mcp/src/log.ts:22-26',
          'packages/core/src/log.ts:10-20',
          'apps/api/src/lib/clerk-api.ts:77',
          'apps/api/wrangler.jsonc:14',
        ],
      },
      {
        text: 'The API’s logs for deep queries name the job ID, template, status and sandbox, never your user ID or the query parameters.',
        refs: ['apps/api/src/routes/deep-query.ts:55-60'],
      },
    ],
  },
  {
    id: 'processors',
    title: 'Who processes data for us',
    statements: [
      {
        text: 'Clerk handles sign-in and holds your account credentials, email address and name. Clerk also sets the session cookies that keep you signed in. We turned Clerk’s telemetry off.',
        refs: ['apps/web/app/lib/auth.tsx:178-184', 'apps/api/src/lib/clerk-api.ts:74-77'],
      },
      {
        text: 'Google processes your sign-in only if you choose to sign in with Google through Clerk. We do not receive anything from Google other than what Clerk passes on as your name and verified email.',
        refs: ['apps/api/src/routes/webhooks-clerk.ts:41-52'],
      },
      {
        text: 'Resend sends our emails, so it receives your address and the content of each email. Resend tells us when an address bounces or complains, and we stop emailing that address.',
        refs: ['apps/notify/src/send.ts:7', 'apps/api/src/routes/webhooks-resend.ts:25-48'],
      },
      {
        text: 'Cloudflare hosts MTI: the web site, API, MCP server and email job run on Cloudflare Workers, our databases are Cloudflare D1, our files are in Cloudflare R2, MCP Tasks use Cloudflare Durable Objects, and the logs are Cloudflare Workers Logs.',
        refs: [
          'apps/web/wrangler.jsonc:19',
          'apps/mcp/wrangler.jsonc:16',
          'apps/api/wrangler.jsonc:47',
          'apps/mcp/src/tasks/client.ts:9',
        ],
      },
      {
        text: 'E2B runs the sandboxes for deep queries. A sandbox is told the job ID and our API address and reads the query’s template and parameters through our API. It is not given your user ID or email address.',
        refs: ['apps/api/src/routes/deep-query.ts:196-222', 'apps/api/src/lib/deep-query.ts:46-49'],
      },
    ],
  },
  {
    id: 'email',
    title: 'Email alerts and how to stop them',
    statements: [
      {
        text: 'We email you only about what you ask for: records, packages and saved searches you have set alerts on, and, if you turn it on, a digest. We also email you a notice when your watchlist is changed through an AI client.',
        refs: [
          'packages/db/migrations/users/0005_watch_events.sql:1-2',
          'apps/notify/src/consume.ts:318',
          'apps/notify/src/consume.ts:407-412',
        ],
      },
      {
        text: 'Alert and digest emails carry an unsubscribe link, which also works as a one-click unsubscribe. You can turn off all instant alerts and digests, only the digest, or a single watched record, package or saved search. Opening the link changes nothing until you confirm it.',
        refs: ['apps/api/src/lib/unsubscribe.ts:4-40', 'apps/api/src/routes/unsubscribe.ts:20-45'],
      },
      {
        text: 'You can also change or switch off alerts at any time on your account page, or delete your account.',
        refs: ['apps/web/app/routes/account.tsx:23', 'apps/api/src/routes/me.ts:80-97'],
      },
    ],
  },
  {
    id: 'mcp',
    title: 'The MCP server and AI clients',
    statements: [
      {
        text: 'MTI has an MCP server so an AI client you connect can look things up for you. You sign in through Clerk to connect it. The AI client then sends us the tool calls it makes (package names and versions, search words, record IDs, watchlist changes) together with your sign-in token. The token goes only to the MCP server, which passes your user ID to the API in a signed message.',
        refs: [
          'apps/mcp/src/api.ts:1',
          'packages/core/src/mcp-user.ts:1',
          'apps/mcp/src/tools/mti_check_packages.ts:21',
        ],
      },
      {
        text: 'Results of long package checks and deep queries run through an AI client are kept as MCP Tasks for at most 90 minutes (70 for deep queries) and then deleted. Your input to a long package check is held with the Task for that time.',
        refs: ['apps/mcp/src/tasks/mcp-task.ts:28-34', 'apps/mcp/src/tasks/mcp-task.ts:177-188'],
      },
      {
        text: 'We do not use anything you send through MCP, or your account data, to train AI models.',
        refs: ['apps/mcp/src/log.ts:22', 'apps/api/src/routes/deep-query.ts:196-199'],
      },
      {
        text: 'Whatever an AI client does with what we send back is governed by that client’s own policy, not ours.',
        refs: ['apps/mcp/src/log.ts:22'],
      },
    ],
  },
  {
    id: 'deleting',
    title: 'Deleting your account, and what remains',
    statements: [
      {
        text: 'You can delete your account on the account page. Deleting removes your account row, watchlist, watched packages, saved searches, queued and sent alert records, package-check counts, watchlist change records and instant-email counts in one step, and then deletes your Clerk account (your sign-in).',
        refs: [
          'apps/api/src/lib/delete-user.ts:15-27',
          'apps/api/src/routes/me.ts:110-121',
          'apps/web/app/routes/account.tsx:289-292',
        ],
      },
      {
        text: 'The same removal runs if your Clerk account is deleted any other way.',
        refs: ['apps/api/src/routes/webhooks-clerk.ts:74'],
      },
      {
        text: 'What remains: for 30 days we keep a block entry holding only your Clerk user ID, so a sign-in token issued before deletion stops working on the MCP server at once. Open MCP Tasks are deleted within 90 minutes of their creation. Deep-query job rows (keyed-hash owner only) and their files remain, as described above. Request logs remain for as long as Cloudflare keeps them. Records sent to AI clients or by email cannot be taken back.',
        refs: [
          'apps/api/src/lib/delete-user.ts:1',
          'apps/api/src/lib/delete-user.ts:29-40',
          'apps/mcp/src/tasks/mcp-task.ts:28-34',
          'apps/api/src/lib/deep-query.ts:46-49',
        ],
      },
      {
        text: 'Backups of account data are kept for [[OWNER: how long account data stays in backups after deletion, or “not kept”]].',
        refs: ['apps/api/src/lib/delete-user.ts:15-27', 'owner-decision'],
      },
    ],
  },
  {
    id: 'cookies',
    title: 'Cookies',
    statements: [
      {
        text: 'Clerk sets its own cookies to keep you signed in. They are needed for sign-in and are set only when you use it.',
        refs: ['apps/web/app/lib/auth.tsx:178-184'],
      },
      {
        text: 'We set one cookie of our own, “ti-theme”, if you choose a light or dark theme. It holds only that choice and lasts one year.',
        refs: [
          'apps/web/app/lib/theme.ts:4-5',
          'apps/web/app/lib/theme.ts:24-26',
          'apps/web/app/components/shell.tsx:277',
        ],
      },
      {
        text: 'If you try an action that needs sign-in while signed out, your browser tab remembers that action in session storage so it can run once after you sign in. It is cleared when it runs or when the tab closes, and it never leaves your browser.',
        refs: ['apps/web/app/lib/intent.ts:18', 'apps/web/app/lib/intent.ts:28-29'],
      },
      {
        text: 'We use no advertising or analytics cookies.',
        refs: ['apps/web/app/lib/security.server.ts:36-49', 'apps/web/app/lib/auth.tsx:183'],
      },
    ],
  },
  {
    id: 'changes',
    title: 'Changes to this page',
    statements: [
      {
        text: `When we change what we collect, we update this page and its “Last updated” date (now ${LAST_UPDATED}). The history is in the public code repository.`,
        refs: ['apps/web/app/lib/privacy-content.ts:6'],
      },
    ],
  },
];
