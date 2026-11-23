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
  const mod = (await import(/* @vite-ignore */ `./${name}.ts`).catch(
    () => null,
  )) as Partial<ParserModule> | null;
  if (!mod || typeof mod.parse !== 'function') throw new Error(`unknown parser: ${name}`);
  return mod as ParserModule;
}
