import { src } from '../define';

// Not wired on purpose. Oracle has no CSAF index, changes.csv or provider metadata. Its only feed is one
// quarterly file (cpu<mon><yyyy>csaf.json, 1.4-5.6 MB) whose URL changes every quarter and whose size passes the
// 5 MB Worker body limit, so it needs the `heavy` pattern with a URL built from the quarter, which is a pattern
// change, plus the E2B `first-load`/`big-file` jobs (still stubs). The `csaf` parser already handles it.
export default src('oracle', 'Oracle', 'Quarterly patches', 'changelist', 'daily', 'ask');
