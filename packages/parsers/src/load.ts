import type { ParsedRecord, ParseResult } from '@ti/core/types';

/** What every `@ti/parsers/<name>` module exports. */
export interface ParserModule {
  parse(input: unknown): ParsedRecord[] | ParseResult<ParsedRecord>;
}

const NAME = /^[a-z0-9][a-z0-9-]*$/;

/**
 * Resolves `SourceConfig.parser` to its module. There is no registry to edit: a new parser is one
 * new file `<name>.ts` in this folder, found by file name. The bundler (esbuild/Vite) sees the
 * relative template import and includes every module in this folder, so keep tests in ../test.
 */
export async function loadParser(name: string): Promise<ParserModule> {
  if (!NAME.test(name)) throw new Error(`invalid parser name: ${name}`);
  let mod: Partial<ParserModule>;
  try {
    mod = (await import(/* @vite-ignore */ `./${name}.ts`)) as Partial<ParserModule>;
  } catch (err) {
    // Only a missing parser module is "unknown". A syntax error, a failing import or a load-time
    // exception in an existing module is a real bug: rethrow it with the original error as the cause.
    if (isModuleNotFound(err, name)) throw new Error(`unknown parser: ${name}`, { cause: err });
    throw new Error(`failed to load parser: ${name}`, { cause: err });
  }
  if (typeof mod.parse !== 'function') throw new Error(`parser ${name} does not export parse()`);
  return mod as ParserModule;
}

/**
 * True when the module that could not be found is this parser's own file, not something that file
 * imports. The runtime names the missing specifier in the message, so compare that to `<name>.ts`.
 */
function isModuleNotFound(err: unknown, name: string): boolean {
  if (!(err instanceof Error)) return false;
  const own = `${name}.ts`;
  const m =
    err.message.match(/Cannot find module ['"]([^'"]+)['"]/) ??
    err.message.match(/Failed to resolve import ['"]([^'"]+)['"]/) ??
    err.message.match(/Failed to load url (\S+)/) ??
    err.message.match(/Unknown variable dynamic import: (\S+)/);
  const specifier = m?.[1];
  return specifier !== undefined && (specifier === `./${own}` || specifier.endsWith(`/${own}`));
}
