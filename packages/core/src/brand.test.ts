import { describe, expect, it } from 'vitest';
import { PRODUCT_INTRO, PRODUCT_NAME, PRODUCT_SHORT } from './brand';

describe('brand', () => {
  it('names the product', () => {
    expect(PRODUCT_SHORT).toBe('MTI');
    expect(PRODUCT_NAME).toBe('Motiontic Threat Index');
    expect(PRODUCT_INTRO).toBe('MTI, the Motiontic Threat Index');
  });
});
