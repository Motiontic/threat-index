export const MAX_BODY_BYTES = 1_048_576;
export const MAX_SBOM_BODY_BYTES = 5_242_880;
export const MAX_HEADER_BYTES = 16_384;
export const MAX_HEADER_VALUE_BYTES = 8_192;
export const MAX_JSON_DEPTH = 32;
export const MAX_CHECK_BODY_BYTES = 3_145_728;
export const MAX_TOOL_INPUT_ELEMENTS = 80_100; // 20,000 packages × 4 plus the wrapper

const enc = new TextEncoder();

export function headersTooLarge(headers: Headers): boolean {
  let total = 0;
  for (const [k, v] of headers) {
    const vb = enc.encode(v).length;
    if (vb > MAX_HEADER_VALUE_BYTES) return true;
    total += enc.encode(k).length + vb;
    if (total > MAX_HEADER_BYTES) return true;
  }
  return false;
}

/**
 * 1 MiB for every tool, 3 MiB for a `tools/call` that names `mti_check_packages` in its headers (read before the
 * body is parsed). `MAX_SBOM_BODY_BYTES` takes over for `mti_check_sbom` when that tool ships.
 */
export function bodyLimitFor(headers: Headers): number {
  return headers.get('mcp-method')?.trim() === 'tools/call' &&
    headers.get('mcp-name')?.trim() === 'mti_check_packages'
    ? MAX_CHECK_BODY_BYTES
    : MAX_BODY_BYTES;
}

/** After parsing: a body over 1 MiB is only allowed for a `tools/call` of `mti_check_packages`. */
export function bodyOverCap(text: string, isCheckCall: boolean): boolean {
  if (isCheckCall || text.length * 3 <= MAX_BODY_BYTES) return false;
  return enc.encode(text).length > MAX_BODY_BYTES;
}

/** Linear scan of `{`/`[` nesting that skips string contents and escapes. */
export function jsonDepthOk(text: string, max: number): boolean {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text.charCodeAt(i);
    if (inString) {
      if (ch === 0x5c) i++;
      else if (ch === 0x22) inString = false;
    } else if (ch === 0x22) inString = true;
    else if (ch === 0x7b || ch === 0x5b) {
      if (++depth > max) return false;
    } else if (ch === 0x7d || ch === 0x5d) depth--;
  }
  return true;
}
