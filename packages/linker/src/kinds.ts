import type {
  AdvisoryRecord,
  IncidentRecord,
  NoticeRecord,
  ParsedRecord,
  SignalRecord,
  TechniqueRecord,
  VulnRecord,
} from '@ti/core/types';

/**
 * `ParsedRecord` has no tag, and `kind` means something different on three of its shapes, so each guard
 * keys on fields only one shape requires. `recordKind` tries them in this order.
 */
type Loose = Record<string, unknown>;
const has = (r: ParsedRecord, field: string): boolean => (r as unknown as Loose)[field] !== undefined;

export const isNoticeRecord = (r: ParsedRecord): r is NoticeRecord => has(r, 'noticeId');
export const isIncidentRecord = (r: ParsedRecord): r is IncidentRecord => has(r, 'incidentId');
export const isAdvisoryRecord = (r: ParsedRecord): r is AdvisoryRecord =>
  has(r, 'sourceId') && has(r, 'status');
export const isTechniqueRecord = (r: ParsedRecord): r is TechniqueRecord =>
  has(r, 'framework') && has(r, 'id');
export const isVulnRecord = (r: ParsedRecord): r is VulnRecord =>
  has(r, 'key') && Array.isArray((r as unknown as Loose).aliases);
export const isSignalRecord = (r: ParsedRecord): r is SignalRecord =>
  has(r, 'vulnKey') && has(r, 'ref') && has(r, 'firstSeen');

export type RecordKind = 'vuln' | 'advisory' | 'signal' | 'notice' | 'incident' | 'technique';

export function recordKind(r: ParsedRecord): RecordKind {
  if (r && typeof r === 'object') {
    if (isNoticeRecord(r)) return 'notice';
    if (isIncidentRecord(r)) return 'incident';
    if (isAdvisoryRecord(r)) return 'advisory';
    if (isTechniqueRecord(r)) return 'technique';
    if (isVulnRecord(r)) return 'vuln';
    if (isSignalRecord(r)) return 'signal';
  }
  throw new Error('linker: unrecognised record');
}
