import { CheckRequestSchema, type CheckResponse } from '@ti/core/packages';
import { openCursor, sealCursor } from '../cursor';
import { arr, obj, root, str } from '../schema';
import { readTaskPage } from '../tasks/client';
import { CHECK_OUTPUT_SCHEMA, formatCheck, pkgIn } from './check-format';
import { rec } from './common';
import { apiJson, asOfFrom, MAX_STRUCTURED_CHARS, type ToolDef } from './shared';

/** One call answers at most this many; more needs a client that supports MCP tasks. */
const MAX_INLINE = 1000;
const MAX_PACKAGES = 20_000;

type Args = { packages?: unknown[]; cursor?: string };

export const tool: ToolDef<Args> = {
  name: 'mti_check_packages',
  enabled: true,
  title: 'Check packages',
  description:
    'Checks package versions against MTI records of known vulnerabilities, malicious packages and exploitation signals. Takes up to 20,000 packages or 3 MiB, each as ecosystem, name and version, or as a purl. Over 1,000 packages is answered as an MCP task, for clients that support tasks. Returns a priority per package (fix_now, fix_soon, plan or note), the version that fixes the matches where one is known, and the matching records. A package with no match is listed under noRecord, which means MTI has no record as of asOf, not that the package is safe. Reachability is not checked.',
  inputSchema: root(obj({ packages: { ...arr(pkgIn, MAX_PACKAGES), minItems: 1 }, cursor: str(512) }, [])),
  outputSchema: CHECK_OUTPUT_SCHEMA,
  async run(args, deps, signal) {
    const secrets = [deps.env.MCP_HMAC_SECRET, deps.env.MCP_HMAC_SECRET_NEXT];
    let offset = 0;
    if (args.cursor !== undefined) {
      const st = await openCursor(
        secrets,
        'mti_check_packages',
        args as Record<string, unknown>,
        args.cursor,
        deps.identity.sub,
      );
      if (!st) return { ok: false, code: 'invalid_argument', field: 'cursor' };
      if ('t' in st) {
        // A task cursor: the next page of a stored result, read from the user's own object. No new task.
        const data = await readTaskPage(deps.env, 'check', deps.identity.sub, st.t, st.o);
        if (!data) return { ok: false, code: 'invalid_argument', field: 'cursor' };
        const n = ['results', 'noRecord', 'rejected'].reduce((m, k) => m + (data[k] as unknown[]).length, 0);
        return { ok: true, data, nOut: n };
      }
      if (!('o' in st)) return { ok: false, code: 'invalid_argument', field: 'cursor' };
      offset = st.o;
    }
    const packages = args.packages;
    if (!packages) return { ok: false, code: 'invalid_argument', field: 'packages' };
    if (packages.length > MAX_INLINE) return { ok: false, code: 'too_many_packages' };
    const body = {
      packages: packages.map((p) => {
        const r = rec(p);
        return 'purl' in r ? { purl: r.purl } : { ecosystem: r.ecosystem, name: r.name, version: r.version };
      }),
    };
    if (!CheckRequestSchema.safeParse(body).success)
      return { ok: false, code: 'invalid_argument', field: 'packages' };

    const res = await apiJson<CheckResponse>(
      deps,
      { method: 'POST', path: '/v1/packages/check', body },
      signal,
    );
    if (!res.ok)
      return {
        ok: false,
        code: res.code,
        retryAfter: res.retryAfter,
        ...(res.code === 'invalid_argument' ? { field: 'packages' } : {}),
      };
    const f = formatCheck(res.body, packages, deps.env);
    const { results, noRecord, rejected, summary, notes } = f;

    // One sequence, results then noRecord, so a cursor offset names a place in it.
    const seq: { r?: (typeof results)[number]['r']; n?: (typeof noRecord)[number]['n'] }[] = [
      ...results.map((x) => ({ r: x.r })),
      ...noRecord.map((x) => ({ n: x.n })),
    ];
    const page = seq.slice(offset);
    const build = (n: number, more: boolean) => ({
      asOf: asOfFrom(f.asOf, deps),
      checked: f.checked ?? packages.length,
      matched: f.matched ?? results.length,
      summary,
      results: page.slice(0, n).flatMap((s) => (s.r ? [s.r] : [])),
      noRecord: page.slice(0, n).flatMap((s) => (s.n ? [s.n] : [])),
      rejected: offset === 0 ? rejected : [],
      truncated: more,
      credits: f.credits,
      notes,
    });
    const size = (n: number, more: boolean) =>
      JSON.stringify({ ...build(n, more), nextCursor: 'x'.repeat(480) }).length;
    let kept = page.length;
    if (size(kept, false) > MAX_STRUCTURED_CHARS) {
      let lo = 0;
      let hi = page.length;
      while (lo < hi) {
        const mid = Math.ceil((lo + hi) / 2);
        if (size(mid, true) <= MAX_STRUCTURED_CHARS) lo = mid;
        else hi = mid - 1;
      }
      kept = Math.max(lo, 1);
    }
    const more = kept < page.length;
    const nextCursor =
      more && deps.env.MCP_HMAC_SECRET
        ? await sealCursor(
            deps.env.MCP_HMAC_SECRET,
            'mti_check_packages',
            args as Record<string, unknown>,
            { o: offset + kept },
            deps.identity.sub,
          )
        : null;
    const data = { ...build(kept, more), nextCursor };
    const ecos = [
      ...new Set([...results.map((x) => x.r.package.ecosystem), ...noRecord.map((x) => x.n.ecosystem)]),
    ].sort();
    deps.stats.ecosystems = ecos.join(',');
    return { ok: true, data, nIn: packages.length, nOut: kept };
  },
};
