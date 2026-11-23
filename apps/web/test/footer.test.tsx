import { NVD_NOTICE } from '@ti/core/licence';
import { renderToString } from 'react-dom/server';
import { StaticRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import { Footer, SAMPLE_BAND_TEXT } from '../app/components/shell';

const rendered = renderToString(
  <StaticRouter location="/">
    <Footer sourceCount={55} />
  </StaticRouter>,
);

// React separates adjacent text nodes with comments; Link adds a data attribute.
const html = rendered.replace(/<!-- -->/g, '').replace(/ data-discover="true"/g, '');

describe('footer', () => {
  it('credits the sources, linking to /sources', () => {
    expect(html).toMatch(/<a href="\/sources">Data from 55 public sources, credited on every\s+page\.<\/a>/);
  });

  it('carries the NVD notice and the licence line with its links', () => {
    expect(html).toContain(NVD_NOTICE);
    expect(html).toContain('Threat Index by Motiontic. Code under Apache-2.0;');
    expect(html).toContain('DATA_LICENSES.md');
    expect(html).toContain('https://github.com/Motiontic/threat-index');
  });

  it('repeats the Explore links for visitors without JavaScript', () => {
    for (const href of ['/', '/index', '/search', '/sources']) expect(html).toContain(`href="${href}"`);
  });

  it('has no inline style', () => {
    expect(html).not.toMatch(/\sstyle=/);
  });
});

describe('sample-data band', () => {
  it('uses the spec wording', () => {
    expect(SAMPLE_BAND_TEXT).toBe(
      'Preview with sample data. Live records arrive when the site is connected to the Threat Index API.',
    );
  });
});
