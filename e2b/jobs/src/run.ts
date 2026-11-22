/**
 * E2B job runner. See docs/IMPLEMENTATION_PLAN.md §6.
 * Usage (in a sandbox or locally): node run.ts '<job-json>'
 */
type JobKind =
  | 'first-load'
  | 'epss-diff'
  | 'big-file'
  | 'nightly-fold'
  | 'search-index'
  | 'compaction'
  | 'deep-query';

interface Job {
  id: string;
  kind: JobKind;
  sourceId?: string;
  apiBase: string; // ti-api, for upload-urls and complete callbacks (HMAC-signed)
  hmac: string; // per-job signature issued by the API; not a long-lived secret
}

const job = JSON.parse(process.argv[2] ?? process.env.JOB_JSON ?? '{}') as Job;

async function main(): Promise<void> {
  if (!job.id || !job.kind) throw new Error('missing job description');
  console.log(JSON.stringify({ level: 'info', msg: 'job start', id: job.id, kind: job.kind }));
  // TODO(M0/M1): per kind — download or read inputs (DuckDB httpfs, read-only R2 token),
  // write Parquet to /tmp, request presigned URLs, upload to lake/ and inbox/, then call complete.
  console.log(JSON.stringify({ level: 'info', msg: 'job done', id: job.id }));
}

main().catch((err) => {
  console.error(JSON.stringify({ level: 'error', msg: String(err), id: job.id }));
  process.exit(1);
});
