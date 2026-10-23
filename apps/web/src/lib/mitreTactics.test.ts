import { describe, expect, it } from 'vitest';
import { OTHER_TACTIC, TACTICS, TACTIC_BY_ID, parentTechnique, tacticsFor } from './mitreTactics';

describe('the tactic list', () => {
  it('has the fourteen enterprise tactics, each once, in matrix order (Command and Control before Exfiltration)', () => {
    expect(TACTICS).toHaveLength(14);
    expect(new Set(TACTICS.map((t) => t.id)).size).toBe(14);
    expect(TACTICS[0].name).toBe('Reconnaissance');
    expect(TACTICS[TACTICS.length - 1].name).toBe('Impact');
    const names = TACTICS.map((t) => t.name);
    expect(names.indexOf('Command and Control')).toBeLessThan(names.indexOf('Exfiltration'));
  });
  it('is indexed by id, and Other is not one of them', () => {
    expect(TACTIC_BY_ID.get('TA0006')?.name).toBe('Credential Access');
    expect(TACTIC_BY_ID.size).toBe(14);
    expect(TACTIC_BY_ID.has(OTHER_TACTIC.id)).toBe(false);
  });
});

describe('tacticsFor', () => {
  it('maps a technique to its tactic, and a technique that does several things to all of them', () => {
    expect(tacticsFor('T1110')).toEqual(['TA0006']);
    expect(tacticsFor('T1078')).toEqual(['TA0001', 'TA0003', 'TA0004', 'TA0005']);
  });
  it('gives a sub-technique its parent\'s tactics', () => {
    expect(tacticsFor('T1059.001')).toEqual(tacticsFor('T1059'));
    expect(tacticsFor('T1078.004')).toEqual(tacticsFor('T1078'));
  });
  it('puts anything it does not know under Other so it is still counted', () => {
    expect(tacticsFor('T9999')).toEqual([OTHER_TACTIC.id]);
    expect(tacticsFor('T9999.001')).toEqual([OTHER_TACTIC.id]);
    expect(tacticsFor('')).toEqual([OTHER_TACTIC.id]);
    expect(tacticsFor('not-a-technique')).toEqual([OTHER_TACTIC.id]);
  });
  it('every technique in the table points only at tactics that exist (no typo can hide a technique)', () => {
    let known = 0;
    for (let n = 1000; n <= 1700; n += 1) {
      const ids = tacticsFor(`T${n}`);
      if (ids[0] === OTHER_TACTIC.id) continue;
      known += 1;
      for (const id of ids) expect(TACTIC_BY_ID.has(id), `T${n} -> ${id}`).toBe(true);
      expect(new Set(ids).size, `T${n} lists a tactic twice`).toBe(ids.length);
    }
    expect(known).toBeGreaterThan(60);
  });
  it('the returned list is the table\'s own, so a caller must not change it: two calls agree', () => {
    expect(tacticsFor('T1110')).toEqual(tacticsFor('T1110'));
  });
});

describe('parentTechnique', () => {
  it('drops the sub-technique, and leaves a plain technique alone', () => {
    expect(parentTechnique('T1078.004')).toBe('T1078');
    expect(parentTechnique('T1078')).toBe('T1078');
    expect(parentTechnique('')).toBe('');
  });
});
