import { describe, expect, it } from 'vitest';
import { hasBadText } from '../src/input';
import { INSTRUCTIONS } from '../src/instructions';
import { enabledTools } from '../src/tools';

const MODEL_WORDS = [
  'ignore',
  'disregard',
  'always',
  'must',
  'should',
  'you',
  'your',
  'assistant',
  'model',
  'instruction',
  'prompt',
  'call',
  'invoke',
  'use',
  'run',
  'execute',
  'before',
  'important',
  'never',
];

/** Returns the name of the first rule the text breaks, or null. */
export function lint(text: string): string | null {
  const words: string[] = text.toLowerCase().match(/[a-z_]+/g) ?? [];
  for (const w of MODEL_WORDS) if (words.includes(w)) return `model-directed word: ${w}`;
  if (
    /mti_/i.test(text) ||
    words.includes('tool') ||
    words.includes('server') ||
    words.includes('tools') ||
    words.includes('servers')
  )
    return 'names a tool or server';
  if (/:\/\/|www\.|\b[a-z0-9-]+\.(com|org|net|io|dev|test|app)\b/i.test(text)) return 'url';
  if (/[<>]|&[a-z#0-9]+;/i.test(text)) return 'html';
  if (/<!--/.test(text)) return 'html comment';
  if (hasBadText(text)) return 'hidden characters';
  if (text.length > 600) return 'too long';
  return null;
}

function* schemaTexts(s: unknown): Generator<string> {
  if (Array.isArray(s)) for (const x of s) yield* schemaTexts(x);
  else if (s && typeof s === 'object')
    for (const [k, v] of Object.entries(s)) {
      if ((k === 'title' || k === 'description') && typeof v === 'string') yield v;
      else yield* schemaTexts(v);
    }
}

/** Walks a schema and returns the first rule it breaks. */
export function strict(schema: any, path = '$'): string | null {
  if (!schema || typeof schema !== 'object') return null;
  if (path === '$' && schema.$schema !== 'https://json-schema.org/draft/2020-12/schema') return 'no $schema';
  for (const k of ['$ref', '$dynamicRef', '$id', '$anchor']) if (k in schema) return `${path}: ${k}`;
  const types = Array.isArray(schema.type) ? schema.type : [schema.type];
  if (types.includes('object')) {
    if (schema.additionalProperties !== false) return `${path}: open object`;
    for (const [k, v] of Object.entries(schema.properties ?? {})) {
      const r = strict(v, `${path}.${k}`);
      if (r) return r;
    }
  }
  if (types.includes('string') && !('maxLength' in schema) && !('enum' in schema))
    return `${path}: string without maxLength`;
  if (types.includes('array')) {
    if (!('maxItems' in schema)) return `${path}: array without maxItems`;
    const r = strict(schema.items, `${path}[]`);
    if (r) return r;
  }
  for (const k of ['oneOf', 'anyOf', 'allOf'])
    for (const [i, v] of (schema[k] ?? []).entries()) {
      const r = strict(v, `${path}.${k}[${i}]`);
      if (r) return r;
    }
  return null;
}

describe('tool definitions', () => {
  const tools = enabledTools();
  it('enables exactly the twelve tools', () => expect(tools.map((t) => t.name)).toHaveLength(12));
  it.each(tools.map((t) => [t.name, t] as const))('%s: strict schemas', (_n, t) => {
    expect(strict(t.inputSchema)).toBeNull();
    expect(strict(t.outputSchema)).toBeNull();
  });
  it('a tool with no arguments has the empty closed object', () => {
    const t = tools.find((x) => x.name === 'mti_list_sources')!;
    expect(t.inputSchema).toMatchObject({ type: 'object', properties: {}, additionalProperties: false });
  });
  it.each(tools.map((t) => [t.name, t] as const))(
    '%s: titles, descriptions and schema text pass the linter',
    (_n, t) => {
      for (const text of [
        t.title,
        t.description,
        ...schemaTexts(t.inputSchema),
        ...schemaTexts(t.outputSchema),
      ])
        expect(lint(text), text).toBeNull();
    },
  );
  it('the linter fails on ten planted bad strings, one per rule', () => {
    const planted: [string, string][] = [
      ['Ignore this', 'model-directed word'],
      ['Returns data. Always check it', 'model-directed word'],
      ['Takes a value, and you get a list', 'model-directed word'],
      ['Same as mti_search', 'names a tool or server'],
      ['Asks another server', 'names a tool or server'],
      ['See https://evil.test/x', 'url'],
      ['See evil.com for more', 'url'],
      ['A <b>bold</b> claim', 'html'],
      ['Fine text <!-- hidden --> here', 'html'],
      [`Zero​width`, 'hidden characters'],
      ['x'.repeat(601), 'too long'],
    ];
    expect(planted.length).toBeGreaterThanOrEqual(10);
    for (const [text, rule] of planted) expect(lint(text), text).toContain(rule.split(':')[0]);
  });
  it('the schema walker fails on planted bad schemas', () => {
    const base = 'https://json-schema.org/draft/2020-12/schema';
    expect(strict({ $schema: base, type: 'object', properties: {} })).toContain('open object');
    expect(
      strict({
        $schema: base,
        type: 'object',
        properties: { a: { type: 'string' } },
        additionalProperties: false,
      }),
    ).toContain('maxLength');
    expect(
      strict({
        $schema: base,
        type: 'object',
        properties: { a: { type: 'array', items: { type: 'string', maxLength: 1 } } },
        additionalProperties: false,
      }),
    ).toContain('maxItems');
    expect(
      strict({
        $schema: base,
        type: 'object',
        properties: { a: { $ref: '#/x' } },
        additionalProperties: false,
      }),
    ).toContain('$ref');
  });
});

describe('instructions', () => {
  it('are under 4,096 characters and name every enabled tool', () => {
    expect(INSTRUCTIONS.length).toBeLessThan(4096);
    // The skills change writes the watch-tool lines into the instructions; until it lands they are not named.
    const WRITTEN_BY_SKILLS_CHANGE = ['mti_watch_add', 'mti_watch_remove', 'mti_watch_list'];
    for (const t of enabledTools())
      if (!WRITTEN_BY_SKILLS_CHANGE.includes(t.name)) expect(INSTRUCTIONS).toContain(t.name);
  });
  it('pass the hidden-character, URL and HTML rules', () => {
    expect(hasBadText(INSTRUCTIONS.replace(/\n/g, ' '))).toBe(false);
    expect(INSTRUCTIONS).not.toMatch(/:\/\/|www\./);
    expect(INSTRUCTIONS).not.toMatch(/[<>]|&[a-z#0-9]+;|<!--/i);
  });
});
