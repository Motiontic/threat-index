import { memorySkillFiles, SkillsExtension } from '@modelcontextprotocol/server/ext/skills';
import { describe, expect, it } from 'vitest';
import { SKILL_FILES } from './skills.generated';

describe('bundled skills', () => {
  it('load through the SDK in strict mode as exactly two skills with name and description only', async () => {
    await SkillsExtension.load(memorySkillFiles({ ...SKILL_FILES }), { prefix: 'mti', strict: true });
    const mds = Object.keys(SKILL_FILES)
      .filter((p) => p.endsWith('/SKILL.md'))
      .sort();
    expect(mds).toEqual(['are-we-affected/SKILL.md', 'safe-install/SKILL.md']);
    for (const n of mds) {
      const m = /^---\nname: (.*)\ndescription: (.*)\n---\n/.exec(SKILL_FILES[n] ?? '');
      expect(m?.[1]).toBe(n.split('/')[0]);
      expect(m?.[2]).toBeTruthy();
    }
  });
});
