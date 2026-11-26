/** Small builders so every tool schema follows the strict rules (closed objects, bounded strings and arrays). */
export type JsonSchema = Record<string, unknown>;
export const DRAFT = 'https://json-schema.org/draft/2020-12/schema';

export const str = (maxLength: number, extra: JsonSchema = {}): JsonSchema => ({
  type: 'string',
  maxLength,
  ...extra,
});
export const nstr = (maxLength: number, extra: JsonSchema = {}): JsonSchema => ({
  type: ['string', 'null'],
  maxLength,
  ...extra,
});
export const num = (extra: JsonSchema = {}): JsonSchema => ({ type: ['number', 'null'], ...extra });
export const int = (extra: JsonSchema = {}): JsonSchema => ({ type: 'integer', ...extra });
export const bool = (): JsonSchema => ({ type: 'boolean' });
export const arr = (items: JsonSchema, maxItems: number): JsonSchema => ({ type: 'array', items, maxItems });
export const obj = (properties: Record<string, JsonSchema>, required?: string[]): JsonSchema => ({
  type: 'object',
  properties,
  required: required ?? Object.keys(properties),
  additionalProperties: false,
});
export const root = (schema: JsonSchema): JsonSchema => ({ $schema: DRAFT, ...schema });

export const CREDITS = arr(obj({ source: str(64), text: str(300), url: nstr(2048) }), 20);
export const COMMON_OUT = { asOf: str(40), credits: CREDITS, notes: arr(str(200), 10) };
