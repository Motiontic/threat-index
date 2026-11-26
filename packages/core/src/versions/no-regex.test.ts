import ts from 'typescript';
import { describe, expect, it } from 'vitest';

interface GlobImportMeta {
  glob(patterns: string[], options: { query: string; import: string; eager: true }): Record<string, string>;
}
const sources = (import.meta as unknown as GlobImportMeta).glob(
  ['./*.ts', '!./*.test.ts', '!./test-support.ts'],
  { query: '?raw', import: 'default', eager: true },
);

describe('no regular expressions in product code', () => {
  it('finds the product files', () => {
    expect(Object.keys(sources).length).toBeGreaterThanOrEqual(18);
  });
  for (const [path, text] of Object.entries(sources)) {
    it(path, () => {
      const file = ts.createSourceFile(path, text, ts.ScriptTarget.ES2022, true);
      const found: string[] = [];
      const visit = (node: ts.Node): void => {
        if (node.kind === ts.SyntaxKind.RegularExpressionLiteral)
          found.push(`regex literal: ${node.getText(file)}`);
        if (ts.isIdentifier(node) && node.text === 'RegExp') found.push('identifier RegExp');
        if (
          ts.isIdentifier(node) &&
          ['localeCompare', 'Intl', 'parseInt', 'BigInt', 'Number'].includes(node.text)
        ) {
          found.push(`forbidden: ${node.text}`);
        }
        ts.forEachChild(node, visit);
      };
      visit(file);
      expect(found).toEqual([]);
    });
  }
  it('no product file imports outside src/versions except ../packages', () => {
    for (const [path, text] of Object.entries(sources)) {
      for (const m of text.matchAll(/from '([^']+)'/g)) {
        const spec = m[1] as string;
        expect(spec.startsWith('./') || spec === '../packages', `${path} imports ${spec}`).toBe(true);
      }
    }
  });
});
