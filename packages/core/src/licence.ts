/**
 * Licence gates. Enforced in the collector (ingest) and in the API (display),
 * never only in the UI.
 */
export type LicenceStatus = 'on' | 'ask' | 'wait' | 'link';
export type DisplayMode = 'full' | 'link' | 'hidden';

export const NVD_NOTICE = 'This product uses the NVD API but is not endorsed or certified by the NVD.';

/** `wait` sources are off until their owner gives written permission. KV overrides win. */
export function canIngest(status: LicenceStatus, override?: boolean): boolean {
  if (override !== undefined) return override;
  return status !== 'wait';
}

/** `link` sources keep only ID, title, date and link. */
export function displayMode(status: LicenceStatus, override?: DisplayMode): DisplayMode {
  if (override) return override;
  if (status === 'wait') return 'hidden';
  if (status === 'link') return 'link';
  return 'full';
}
