/**
 * fixture(source, file) returns the text of fixtures/<source>/<file>. It works in `pnpm test` (Node)
 * and `pnpm test:workers` (workerd), because Vite inlines the files at transform time.
 */
interface GlobImportMeta {
  glob(pattern: string, options: { query: string; import: string; eager: true }): Record<string, string>;
}

const files = (import.meta as unknown as GlobImportMeta).glob('../fixtures/*/*', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export function fixture(source: string, file: string): string {
  const text = files[`../fixtures/${source}/${file}`];
  if (text === undefined) throw new Error(`no fixture fixtures/${source}/${file}`);
  return text;
}
