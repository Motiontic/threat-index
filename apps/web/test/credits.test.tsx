import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { CreditList } from '../app/components/ui';

const html = (url?: string) =>
  renderToString(
    <CreditList credits={[{ sourceId: 's', name: 'Src', text: 'Credit text', ...(url ? { url } : {}) }]} />,
  );

describe('CreditList', () => {
  it('links the name only for https URLs', () => {
    expect(html('https://example.com/a')).toContain('<a href="https://example.com/a"');
    for (const bad of [
      'http://example.com',
      'javascript:alert(1)',
      'data:text/html,x',
      'not a url',
      '//example.com',
    ])
      expect(html(bad), bad).not.toContain('<a ');
    expect(html()).not.toContain('<a ');
  });

  it('writes the name, then the text', () => {
    const out = html();
    expect(out.indexOf('Src')).toBeLessThan(out.indexOf('Credit text'));
  });
});
