/** A same-site path from untrusted input: must start with one `/` and not `//` or `/\`; otherwise `/`. */
export function localPath(value: string | null | undefined): string {
  if (!value || value.length > 500) return '/';
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/';
  if ([...value].some((c) => c.charCodeAt(0) < 32)) return '/';
  return value;
}
