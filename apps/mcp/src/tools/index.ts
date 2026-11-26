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
