// Fails when `fetch(` appears where a request path could turn into URL fetching (SSRF):
//   - apps/mcp/src, except src/api.ts (the one place ti-mcp calls ti-api, over a service binding);
//   - apps/api/src, except the files below, which use it today for fixed, known addresses.
// Run by `pnpm lint`. Method definitions (`async fetch(request ...)`, the Worker and Durable Object entry
// points) are not calls and are ignored; comments are ignored.
//
//   node scripts/check-no-fetch.mjs
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = fileURLToPath(new URL('..', import.meta.url));

/** Per source folder, the files (relative to it) that may call fetch. */
export const RULES = [
  { dir: 'apps/mcp/src', allowed: ['api.ts'] },
  // Today: the Clerk Backend API client, which calls one fixed address.
  { dir: 'apps/api/src', allowed: ['lib/clerk-api.ts'] },
];

const SOURCE = /\.(?:ts|tsx|mts|cts|js|mjs|cjs)$/;

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules') yield* walk(path);
    } else if (SOURCE.test(entry.name)) yield path;
  }
}

/** Source text with comments blanked out (line breaks kept, so line numbers stay right). */
function withoutComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:'"`\\])\/\/[^\n]*/g, (m, lead) => lead + ' '.repeat(m.length - lead.length));
}

/** Every `fetch(` call outside the allowed files: [{ file, line }]. */
export function findViolations(root = ROOT, rules = RULES) {
  const found = [];
  for (const { dir, allowed } of rules) {
    const base = join(root, dir);
    if (!existsSync(base)) continue;
    for (const file of walk(base)) {
      const rel = relative(base, file).split('\\').join('/');
      if (allowed.includes(rel)) continue;
      withoutComments(readFileSync(file, 'utf8'))
        .split('\n')
        .forEach((line, i) => {
          if (/\bfetch\s*\(/.test(line) && !/\basync\s+fetch\s*\(/.test(line))
            found.push({ file: `${dir}/${rel}`, line: i + 1 });
        });
    }
  }
  return found;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const found = findViolations();
  if (found.length > 0) {
    for (const { file, line } of found) console.error(`${file}:${line}: fetch( is not allowed here`);
    console.error(
      '\nURL fetching from a request path is blocked. In apps/mcp, call ti-api through src/api.ts (callApi).\n' +
        'If a file in apps/api/src really needs fetch, add it to RULES in scripts/check-no-fetch.mjs and say why in review.',
    );
    process.exit(1);
  }
  console.log('check-no-fetch: ok');
}
