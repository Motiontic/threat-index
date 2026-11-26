import { tool as mti_check_packages } from './mti_check_packages';
import { tool as mti_check_sbom } from './mti_check_sbom';
import { tool as mti_deep_query } from './mti_deep_query';
import { tool as mti_get_entry } from './mti_get_entry';
import { tool as mti_get_technique } from './mti_get_technique';
import { tool as mti_latest_threats } from './mti_latest_threats';
import { tool as mti_list_sources } from './mti_list_sources';
import { tool as mti_search } from './mti_search';
import { tool as mti_search_breaches } from './mti_search_breaches';
import { tool as mti_search_incidents } from './mti_search_incidents';
import { tool as mti_watch_add } from './mti_watch_add';
import { tool as mti_watch_list } from './mti_watch_list';
import { tool as mti_watch_remove } from './mti_watch_remove';
import type { ToolDef } from './shared';

/** The fixed order tools are listed in. A tool is enabled by its own change, which flips `enabled` in its file. */
export const TOOL_ORDER = [
  'mti_check_packages',
  'mti_check_sbom',
  'mti_get_entry',
  'mti_search',
  'mti_latest_threats',
  'mti_search_breaches',
  'mti_search_incidents',
  'mti_get_technique',
  'mti_list_sources',
  'mti_watch_add',
  'mti_watch_remove',
  'mti_watch_list',
  'mti_deep_query',
] as const;
export type ToolName = (typeof TOOL_ORDER)[number];

type Stub = { readonly name: ToolName; readonly enabled: false };
export const TOOLS: Record<ToolName, ToolDef<never> | Stub> = {
  mti_check_packages,
  mti_check_sbom,
  mti_get_entry,
  mti_search,
  mti_latest_threats,
  mti_search_breaches,
  mti_search_incidents,
  mti_get_technique,
  mti_list_sources,
  mti_watch_add,
  mti_watch_remove,
  mti_watch_list,
  mti_deep_query,
};

export function enabledTools(): ToolDef<never>[] {
  const out: ToolDef<never>[] = [];
  for (const name of TOOL_ORDER) {
    const t = TOOLS[name];
    if (t.enabled) out.push(t);
  }
  return out;
}
