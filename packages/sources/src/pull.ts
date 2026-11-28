import type { JobRequest } from '@ti/core/control';
import type { CredentialName } from '@ti/core/types';

/**
 * How one source is pulled, as data. Each pattern reads only its own block; the generic code in
 * `@ti/patterns` holds no source-specific URLs, selectors or columns.
 */
export interface PullConfig {
  /** GitHub only. `repo` is 'owner/name'; `branch` defaults to 'main'; `include` takes globs. */
  git?: {
    repo: string;
    branch?: string;
    include: string[];
    /** Most files matching `include` an archive load reads. Default 400,000; hard ceiling 1,000,000. */
    maxFiles?: number;
    /** Most uncompressed bytes an archive load reads. Default 4 GiB; hard ceiling 20 GiB. */
    maxBytes?: number;
  };
  /** A newest-first CSV list. Columns are zero-based; `itemUrl` has a `{ref}` placeholder. */
  changelist?: {
    listUrl: string;
    timeColumn: number;
    refColumn: number;
    itemUrl: string;
    rangeBytes?: number;
    /** Keep only lines whose ref's text before the first `/` is listed. */
    refPrefixes?: string[];
  };
  since?: {
    url: string;
    startParam: string;
    endParam?: string;
    offsetParam: string;
    limitParam: string;
    /** Dotted paths into the response. */
    itemsPath: string;
    idPath: string;
    totalPath?: string;
    maxWindowDays?: number;
    lookbackDays?: number;
    auth?: { header: string; credential: CredentialName };
  };
  fingerprint?: {
    url: string;
    format: 'json' | 'csv';
    itemsPath?: string;
    key: string;
    /** Regex; group 1 is the version, read from the first `bytes` bytes. */
    version?: { bytes: number; pattern: string };
  };
  feed?: { url: string; order?: 'newest-first' | 'oldest-first' };
  page?: {
    url: string;
    item: string;
    key: string;
    order?: 'newest-first' | 'oldest-first';
    fields: Record<string, string | { selector: string; attr: string }>;
  };
  heavy?: { url: string; version?: { url: string; pattern: string; bytes?: number } };
  /** For `heavy: true` sources. Default 'big-file'. */
  jobKind?: JobRequest['kind'];
}
