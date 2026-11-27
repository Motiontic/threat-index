// Bundles apps/mcp/skills into the MCP server and the Claude Code plugin.
//   node scripts/bundle-skills.mjs          write the generated files
//   node scripts/bundle-skills.mjs --check  fail if the committed files are stale
// Every rule here guards text that is served to AI agents as instructions. See SPEC.md (mcp-skills).
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const MTI_ORIGIN = 'https://mti.motiontic.com/';
export const MCP_URL = 'https://mti.motiontic.com/mcp';
export const DOCS_URL = 'https://mti.motiontic.com/docs/mcp';
export const MAX_FILE_BYTES = 100 * 1024;
export const MAX_SKILL_BYTES = 400 * 1024;
export const GENERATED_TS = 'apps/mcp/src/skills.generated.ts';
export const PLUGIN_DIR = 'plugins/mti';

export class BundleError extends Error {
  constructor(file, rule) {
    super(`${file}: ${rule}`);
    this.name = 'BundleError';
    this.file = file;
    this.rule = rule;
  }
}

/** Command words that may not start a line or an inline code span. Shared with the tests. */
export const SHELL_WORDS = [
  'npm',
  'pnpm',
  'yarn',
  'npx',
  'pip',
  'pip3',
  'pipx',
  'uv',
  'poetry',
  'go',
  'cargo',
  'curl',
  'wget',
  'sudo',
  'git',
  'bash',
  'sh',
  'zsh',
  'node',
  'python',
  'python3',
  'docker',
  'brew',
  'apt',
  'apt-get',
  'make',
  'gem',
  'bundle',
  'composer',
  'dotnet',
  'mvn',
  'gradle',
  'mix',
  'dart',
  'flutter',
  'swift',
  'rm',
  'cat',
];
const LEAD = /^\s*(?:[-*+>] |\d+[.)] )/;

/** Strips list and quote markers repeatedly, then returns the command word the line starts like, or null. */
export function shellStart(line) {
  let s = line;
  while (LEAD.test(s)) s = s.replace(LEAD, '');
  s = s.trim();
  if (s.startsWith('$ ')) return '$';
  const w = /^([A-Za-z0-9_-]+) /.exec(s);
  return w && SHELL_WORDS.includes(w[1].toLowerCase()) ? w[1] : null;
}

/** First shell-looking start on a line or inside an inline code span of it, or null. */
export function shellProblemInLine(line) {
  const hit = shellStart(line);
  if (hit) return hit;
  for (const m of line.matchAll(/`([^`]*)`/g)) {
    const h = shellStart(m[1]);
    if (h) return h;
  }
  return null;
}

/** Rules on the text of one file. Returns the first rule broken, or null. Pure: no disk. */
export function textProblem(text) {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c !== 10 && (c < 0x20 || c > 0x7e))
      return `character U+${c.toString(16).toUpperCase().padStart(4, '0')} is not printable ASCII or a newline`;
  }
  if (text.includes('<')) return 'contains "<" (no HTML, including comments)';
  const rest = text.split(MTI_ORIGIN).join('');
  if (/:\/\/|\/\/|\\|www\.|mailto:|javascript:|data:/i.test(rest))
    return `links must go to ${MTI_ORIGIN} only`;
  for (const m of text.matchAll(/\]\(([^)]*)\)|\]:[ \t]*(\S*)/g)) {
    const target = (m[1] ?? m[2] ?? '').trim();
    const mti = target.startsWith(MTI_ORIGIN);
    const rel = /^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*(#[a-z0-9-]+)?$/.test(target);
    if (!mti && !rel)
      return `link target is not an MTI URL or a relative path in the skill: ${target.slice(0, 30)}`;
  }
  for (const line of text.split('\n')) {
    if (/^\s*(```|~~~)/.test(line)) return 'code fences are not allowed';
    if (/^( {4}|\t)/.test(line)) return 'lines indented by 4 spaces or a tab are not allowed';
    const hit = shellProblemInLine(line);
    if (hit) return `line or code span starts like a shell command: ${hit}`;
  }
  // The word "install" is only allowed as part of the skill name.
  if (/install/i.test(text.replace(/safe-install/g, '')))
    return 'the word "install" is only allowed in "safe-install"';
  return null;
}

/** Frontmatter rules for a SKILL.md. Returns the first rule broken, or null. */
export function frontmatterProblem(text, skill) {
  const lines = text.split('\n');
  if (lines[0] !== '---') return 'SKILL.md must start with a "---" frontmatter line';
  const end = lines.indexOf('---', 1);
  if (end < 0) return 'frontmatter is not closed with "---"';
  const keys = [];
  const values = {};
  for (const l of lines.slice(1, end)) {
    const m = /^([A-Za-z0-9_-]+): (.*)$/.exec(l);
    if (!m) return `frontmatter line is not "key: value": ${l.slice(0, 30)}`;
    keys.push(m[1]);
    values[m[1]] = m[2];
  }
  if (keys.length !== 2 || !keys.includes('name') || !keys.includes('description'))
    return `frontmatter must have exactly name and description (found: ${keys.join(', ') || 'none'})`;
  if (values.name !== skill) return `frontmatter name must equal the folder name "${skill}"`;
  const d = values.description;
  if (d.length === 0 || d.length > 1024) return 'description must be 1 to 1024 characters';
  if (/[#'"`]|: /.test(d) || d !== d.trim())
    return 'description must be one plain line: no #, ": " or quotes';
  if (/^[[{|>!&*\-?%@]/.test(d))
    return 'description must be a plain scalar: it cannot start with [ { | > ! & * - ? % or @';
  if (/^(true|false|null|yes|no|on|off)$/i.test(d)) return 'description must not be a YAML keyword';
  return null;
}

/** Path segment rules. `path` is `<skill>/<rest>`. Returns the first rule broken, or null. */
export function pathProblem(path) {
  const segs = path.split('/');
  for (const [i, s] of segs.entries()) {
    if (i === segs.length - 1 && s === 'SKILL.md') continue;
    if (!/^[a-z0-9][a-z0-9._-]*$/.test(s)) return `path segment "${s}" must match ^[a-z0-9][a-z0-9._-]*$`;
  }
  const skillMds = segs.filter((s) => s === 'SKILL.md');
  if (skillMds.length && segs.length !== 2) return 'SKILL.md is only allowed directly inside a skill folder';
  return null;
}

function sha(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function walk(dir, rel, out, skill) {
  for (const name of readdirSync(dir).sort()) {
    const abs = join(dir, name);
    const path = `${rel}/${name}`;
    const st = lstatSync(abs);
    if (st.isSymbolicLink()) throw new BundleError(path, 'symlinks are not allowed');
    if (st.isDirectory()) walk(abs, path, out, skill);
    else if (st.isFile()) out.push({ abs, path });
    else throw new BundleError(path, 'only regular files are allowed');
  }
}

function checkFile(path, bytes, kind) {
  const pp = kind === 'skill' ? pathProblem(path) : null;
  if (pp) throw new BundleError(path, pp);
  if (!path.endsWith('.md')) throw new BundleError(path, 'only markdown (.md) files are allowed');
  if (bytes.length > MAX_FILE_BYTES) throw new BundleError(path, `file is over ${MAX_FILE_BYTES} bytes`);
  const text = bytes.toString('latin1');
  // A UTF-8 file with non-ASCII bytes decodes to latin1 characters above 0x7e; the ASCII rule rejects them.
  const p = textProblem(text);
  if (p) throw new BundleError(path, p);
  return { text, kind };
}

/**
 * Reads and checks everything under `skillsDir`. Throws BundleError on the first problem.
 * Returns the files (`<skill>/<path>` -> text), their digests, the bundle digest and the plugin README text.
 */
export function collect(skillsDir) {
  const root = resolve(skillsDir);
  const files = {};
  const digests = {};
  let pluginReadme;
  for (const name of readdirSync(root).sort()) {
    const abs = join(root, name);
    const st = lstatSync(abs);
    if (st.isSymbolicLink()) throw new BundleError(name, 'symlinks are not allowed');
    if (st.isFile()) {
      if (name === 'CHANGELOG.md') continue;
      if (name === 'PLUGIN_README.md') {
        pluginReadme = checkFile(name, readFileSync(abs), 'readme').text;
        continue;
      }
      throw new BundleError(name, 'unexpected file next to the skill folders');
    }
    if (!st.isDirectory()) throw new BundleError(name, 'only regular files and folders are allowed');
    const found = [];
    walk(abs, name, found, name);
    let total = 0;
    let hasSkillMd = false;
    for (const f of found) {
      const bytes = readFileSync(f.abs);
      const { text } = checkFile(f.path, bytes, 'skill');
      total += bytes.length;
      if (f.path === `${name}/SKILL.md`) {
        hasSkillMd = true;
        const fm = frontmatterProblem(text, name);
        if (fm) throw new BundleError(f.path, fm);
      }
      files[f.path] = text;
      digests[f.path] = sha(bytes);
    }
    if (!hasSkillMd) throw new BundleError(name, 'skill folder has no SKILL.md');
    if (total > MAX_SKILL_BYTES) throw new BundleError(name, `skill is over ${MAX_SKILL_BYTES} bytes`);
  }
  if (Object.keys(files).length === 0) throw new BundleError('skills', 'no skills found');
  const lines = Object.keys(digests)
    .sort()
    .map((p) => `${p} ${digests[p]}\n`)
    .join('');
  return { files, digests, bundleDigest: sha(Buffer.from(lines, 'utf8')), pluginReadme };
}

const ENTRY = /^## (\d+)\.(\d+)\.(\d+) - (sha256:[0-9a-f]{64})$/;

/** The first "## " header is the newest entry and must name the bundle digest. Versions rise bottom to top. */
export function checkChangelog(skillsDir, bundleDigest) {
  let text;
  try {
    text = readFileSync(join(skillsDir, 'CHANGELOG.md'), 'utf8');
  } catch {
    throw new BundleError('CHANGELOG.md', `missing. Add an entry "## <semver> - ${bundleDigest}"`);
  }
  const heads = text.split('\n').filter((l) => l.startsWith('## '));
  if (heads.length === 0)
    throw new BundleError('CHANGELOG.md', `no entry like "## <semver> - ${bundleDigest}"`);
  const parsed = heads.map((h) => ENTRY.exec(h.trimEnd()));
  const bad = parsed.findIndex((m) => !m);
  if (bad >= 0)
    throw new BundleError(
      'CHANGELOG.md',
      `entry is not "## <semver> - sha256:<hex>": ${heads[bad].slice(0, 40)}`,
    );
  const vers = parsed.map((m) => [Number(m[1]), Number(m[2]), Number(m[3])]);
  for (let i = 0; i + 1 < vers.length; i++) {
    const [x, y] = [vers[i], vers[i + 1]];
    const up = x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
    if (up <= 0)
      throw new BundleError(
        'CHANGELOG.md',
        `versions must strictly increase from bottom to top (${heads[i + 1].slice(3, 9)} then ${heads[i].slice(3, 9)})`,
      );
  }
  const m = parsed[0];
  if (m[4] !== bundleDigest)
    throw new BundleError(
      'CHANGELOG.md',
      `newest entry names ${m[4]} but the bundle digest is ${bundleDigest}. Add a new entry for it`,
    );
  return `${m[1]}.${m[2]}.${m[3]}`;
}

function generatedTs({ files, digests, bundleDigest }) {
  const obj = (o) =>
    `{\n${Object.keys(o)
      .sort()
      .map((k) => `  ${JSON.stringify(k)}: ${JSON.stringify(o[k])},`)
      .join('\n')}\n}`;
  return `// GENERATED by scripts/bundle-skills.mjs from apps/mcp/skills. DO NOT EDIT.
// Edit the skill files, add a CHANGELOG.md entry, then run \`pnpm skills:bundle\`.

export const SKILL_FILES: Readonly<Record<string, string>> = Object.freeze(${obj(files)});

export const SKILL_DIGESTS: Readonly<Record<string, string>> = Object.freeze(${obj(digests)});

export const BUNDLE_DIGEST = ${JSON.stringify(bundleDigest)};
`;
}

/** Everything the bundler writes, as repo-relative path -> text. Checks every rule first. */
export function build(skillsDir) {
  const c = collect(skillsDir);
  const version = checkChangelog(skillsDir, c.bundleDigest);
  const out = {};
  out[GENERATED_TS] = generatedTs(c);
  out[`${PLUGIN_DIR}/.claude-plugin/plugin.json`] = `${JSON.stringify(
    {
      name: 'mti',
      description:
        'MTI (Motiontic Threat Index): check project lockfiles and single packages against known vulnerabilities and malicious packages.',
      version,
      homepage: DOCS_URL,
    },
    null,
    2,
  )}\n`;
  out[`${PLUGIN_DIR}/.mcp.json`] = JSON.stringify({ mcpServers: { mti: { type: 'http', url: MCP_URL } } });
  if (c.pluginReadme === undefined) throw new BundleError('PLUGIN_README.md', 'missing');
  out[`${PLUGIN_DIR}/README.md`] = c.pluginReadme;
  for (const [p, text] of Object.entries(c.files)) out[`${PLUGIN_DIR}/skills/${p}`] = text;
  return out;
}

function main() {
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const check = process.argv.includes('--check');
  let out;
  try {
    out = build(join(repo, 'apps/mcp/skills'));
  } catch (e) {
    if (e instanceof BundleError) {
      console.error(`bundle-skills: ${e.message}`);
      process.exit(1);
    }
    throw e;
  }
  if (check) {
    let stale = 0;
    for (const [p, text] of Object.entries(out)) {
      let have = null;
      try {
        have = readFileSync(join(repo, p), 'utf8');
      } catch {}
      if (have !== text) {
        console.error(`stale: ${p}`);
        stale++;
      }
    }
    if (stale) process.exit(1);
    return;
  }
  rmSync(join(repo, PLUGIN_DIR), { recursive: true, force: true });
  for (const [p, text] of Object.entries(out)) {
    mkdirSync(dirname(join(repo, p)), { recursive: true });
    writeFileSync(join(repo, p), text);
  }
  console.log(
    `wrote ${Object.keys(out).length} files (${relative(repo, join(repo, GENERATED_TS))} and ${PLUGIN_DIR})`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
