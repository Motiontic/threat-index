export type DataMode = 'api' | 'fixtures';

/**
 * `'api'` only when the deploy asks for it AND the service binding exists. A misconfigured deploy falls back
 * to fixtures, which shows the sample band and stays out of search engines.
 */
export function dataMode(bindings: { DATA_SOURCE?: string; API?: Fetcher }): DataMode {
  return bindings.DATA_SOURCE === 'api' && bindings.API ? 'api' : 'fixtures';
}
