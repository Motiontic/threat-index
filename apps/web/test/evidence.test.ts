import { describe, expect, it } from 'vitest';
import { groupEvidence } from '../app/lib/evidence';

const sig = (kind: string, ref: string) => ({ kind, source: 's', ref, firstSeen: '2025-01-01' });

describe('groupEvidence', () => {
  it('keeps exploited, exploit code and detections in separate groups, in that order', () => {
    const ev = groupEvidence({
      kevAdded: '2025-05-05',
      signals: [
        sig('detection', 'd1'),
        sig('poc', 'p1'),
        sig('ransomware', 'r1'),
        sig('public_exploit', 'e1'),
        sig('exploited_wild', 'w1'),
      ],
    });
    expect(ev.groups.map((g) => g.id)).toEqual(['exploited', 'exploit-code', 'detections']);
    expect(ev.groups[0]?.items.map((i) => i.ref)).toEqual(['r1', 'w1']);
    expect(ev.groups[1]?.items.map((i) => i.ref)).toEqual(['p1', 'e1']);
    expect(ev.groups[2]?.items.map((i) => i.ref)).toEqual(['d1']);
    expect(ev.groups[0]?.kevAdded).toBe('2025-05-05');
  });

  it('shows EPSS apart, as a prediction, and never inside a group', () => {
    const ev = groupEvidence({ epss: 0.42, signals: [sig('detection', 'd1')] });
    expect(ev.prediction).toEqual({ epss: 0.42 });
    expect(JSON.stringify(ev.groups)).not.toContain('0.42');
    expect(groupEvidence({ signals: [] }).prediction).toBeNull();
  });

  it('puts unknown kinds under Other signals', () => {
    const ev = groupEvidence({ signals: [sig('sighting', 'x'), sig('detection', 'd')] });
    expect(ev.groups.map((g) => g.id)).toEqual(['detections', 'other']);
    expect(ev.groups[1]?.title).toBe('Other signals');
  });

  it('shows the KEV date even with no exploited signal rows', () => {
    const ev = groupEvidence({ kevAdded: '2025-05-05', signals: [] });
    expect(ev.groups).toHaveLength(1);
    expect(ev.groups[0]).toMatchObject({ id: 'exploited', kevAdded: '2025-05-05', items: [] });
  });

  it('is empty when there is nothing', () => {
    expect(groupEvidence({ signals: [] })).toEqual({ groups: [], prediction: null });
  });

  it('carries a link only when the signal has one', () => {
    const ev = groupEvidence({ signals: [{ ...sig('poc', 'p'), url: 'https://x.test/' }, sig('poc', 'q')] });
    expect(ev.groups[0]?.items[0]?.url).toBe('https://x.test/');
    expect(ev.groups[0]?.items[1]).not.toHaveProperty('url');
  });
});
