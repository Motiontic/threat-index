import { createContext, useContext } from 'react';

const NonceContext = createContext<string>('');

/** Carries the per-request CSP nonce to `<Scripts>` and friends without putting it in loader data. */
export const NonceProvider = NonceContext.Provider;

export function useNonce(): string {
  return useContext(NonceContext);
}
