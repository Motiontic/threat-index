import type { Credit } from './api';
import type { CountUnit } from './types';

/** Shared JSON shapes for the public breach, incident and technique routes. No type here has a total. */
export type { CountUnit };

export interface BreachCount {
  unit: CountUnit;
  jurisdiction: string | null;
  count: number;
}
export interface BreachNotice {
  source: string;
  noticeId: string;
  name: string;
  display: 'full' | 'link';
  notified?: string;
  url?: string; // link and full
  occurredFrom?: string; // full only from here
  occurredTo?: string;
  discovered?: string;
  count?: number;
  countUnit?: CountUnit;
  jurisdiction?: string;
  dataTypes?: string[];
}
export interface BreachSummary {
  key: string;
  company: { key: string; name: string } | null;
  firstSeen: string;
  dates?: { from: string; to: string };
  noticeCount: number; // visible notices only
  counts: BreachCount[];
  jurisdictions: string[];
  sources: string[];
}
export interface BreachDetail extends BreachSummary {
  notices: BreachNotice[];
  credits: Credit[];
}
export type IncidentKind = 'ai' | 'cyber_op' | 'cyber_event';
export interface IncidentSummary {
  source: string;
  incidentId: string;
  kind: IncidentKind;
  title: string;
  date?: string;
  url?: string;
  display: 'full' | 'link';
}
export interface IncidentDetail extends IncidentSummary {
  entities: string[];
  techniques: { id: string; name?: string }[]; // both [] when link
  credits: Credit[];
}
export type Framework = 'attack' | 'atlas' | 'cwe' | 'capec';
export interface TechniqueSummary {
  id: string;
  framework: Framework;
  name: string;
  parent?: string;
}
export interface TechniqueDetail extends TechniqueSummary {
  summary?: string;
  parentRef?: { id: string; name: string };
  children: TechniqueSummary[];
  vulns: { key: string; title: string; cvss?: number; exploited: boolean }[];
  vulnsMore: boolean;
  credits: Credit[];
}
export interface WorldList<T> {
  items: T[];
  page: number;
  next: number | null;
  credits: Credit[];
}
