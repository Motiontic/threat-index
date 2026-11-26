export const CAPS = { title: 200, summary: 600, name: 200, short: 120 } as const;

const ESC = '\u001b';
const OSC = new RegExp(`(?:${ESC}\\]|\\u009d)[^\\u0007\\u001b\\u009c]*(?:\\u0007|${ESC}\\\\|\\u009c|$)`, 'g');
const CSI = new RegExp(`(?:${ESC}\\[|\\u009b)[0-?]*[ -/]*[@-~]?`, 'g');
const ESC2 = new RegExp(`${ESC}[ -~]?`, 'g');
// biome-ignore lint/suspicious/noControlCharactersInRegex: stripping controls is the point
const CONTROLS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;
const HIDDEN = /\p{Default_Ignorable_Code_Point}|\p{Cf}|\p{Co}|\p{Cn}/gu;
const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-fA-F]{1,6}|#\d{1,7}|[a-zA-Z]{2,6});/g, (m, body: string) => {
    if (body.startsWith('#')) {
      const n =
        body[1] === 'x' || body[1] === 'X' ? Number.parseInt(body.slice(2), 16) : Number(body.slice(1));
      return Number.isInteger(n) && n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : ' ';
    }
    return ENTITIES[body.toLowerCase()] ?? m;
  });
}

const URL_LIKE = [
  /\b[a-z][a-z0-9+.-]{0,15}:?[\\/]{2,}\S*/gi,
  /(?<![\w:])[\\/]{2}[\w.-]+\S*/g,
  /\bwww\.\S*/gi,
  /\b(?:https?|ftp|ftps|wss?|sftp):[\\/]?[^\s\\/]\S*/gi,
  /\b(?:javascript|data|vbscript|file|mailto|blob|about):\S*/gi,
  /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?[\\/]\S*/g,
  /\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]{1,62}(?::\d+)?[\\/]\S*/gi,
];

/** One pass of the whole strip. Run repeatedly by `clean` until nothing changes. */
function pass(input: string): string {
  let s = input.normalize('NFKC');
  s = s.replace(OSC, '').replace(CSI, '').replace(ESC2, '');
  // Reference definitions are matched while lines still exist. Only the `[label]:` marker goes here; a URL
  // token after it is removed by the URL rules below, and any other text stays.
  s = s.replace(/^[ \t]*\[[^\]\n]+\]:[ \t]*/gm, ' ');
  s = s.replace(/[\t\n\r]/g, ' ').replace(CONTROLS, '');
  s = s.replace(HIDDEN, '');
  s = decodeEntities(s);
  s = s.replace(CONTROLS, '').replace(HIDDEN, '');
  s = s.replace(/<!--[\s\S]*?(?:-->|$)/g, ' ');
  s = s.replace(/<[^>]*>/g, ' ').replace(/[<>]/g, '');
  s = s.replace(/!\[[^\]]*\]\([^)]*\)/g, ' ');
  s = s.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1');
  s = s.replace(/`/g, '');
  for (const re of URL_LIKE) s = s.replace(re, '[link removed]');
  return s.replace(/\s+/g, ' ').trim();
}

/** Cleans one outside string for a model: no escapes, hidden characters, markup, links or overlong text. */
export function clean(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  let s = value;
  for (let i = 0; i < 3; i++) {
    const next = pass(s);
    if (next === s) break;
    s = next;
  }
  const cps = [...s];
  if (cps.length > max) s = `${cps.slice(0, max - 1).join('')}…`;
  return s === '' ? null : s;
}
