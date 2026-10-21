import { describe, expect, it } from 'vitest';
import type { Case } from '@/lib/api';
import { actNow, workOrder } from './act-now';

const c = (over: Partial<Case>): Case => ({ id: 'x', title: 'A case', status: 'open', severity: 'medium', createdAt: '2026-10-01T00:00:00Z', updatedAt: '2026-10-01T00:00:00Z', ...over }) as Case;

describe('workOrder', () => {
  it('puts the most severe first, then a case nobody owns before one somebody does, then the oldest', () => {
    const list = [
      c({ id: 'low', severity: 'low' }),
      c({ id: 'med-owned', assignee: 'a@x.com' }),
      c({ id: 'med-new', createdAt: '2026-10-10T00:00:00Z' }),
      c({ id: 'med-old', createdAt: '2026-09-01T00:00:00Z' }),
      c({ id: 'crit-owned', severity: 'critical', assignee: 'a@x.com' }),
      c({ id: 'high', severity: 'high' }),
    ];
    expect(list.sort(workOrder).map((x) => x.id)).toEqual(['crit-owned', 'high', 'med-old', 'med-new', 'med-owned', 'low']);
  });
});

describe('actNow', () => {
  it('says how many are open and unowned and which to start with, counting only cases still to deal with', () => {
    const board = actNow([
      c({ id: '1', title: 'Ransomware Attempt', severity: 'critical' }),
      c({ id: '2', title: 'Phish', severity: 'high', assignee: 'e@x.com' }),
      c({ id: '3', title: 'Old one', status: 'resolved', severity: 'critical' }),
      c({ id: '4', title: 'Shut', status: 'closed' }),
      c({ id: '5', title: 'Waiting', status: 'pending', severity: 'low' }),
      c({ id: '6', title: 'Busy', status: 'in_progress', severity: 'low', assignee: 'z@x.com' }),
    ]);
    expect(board.open).toBe(4);
    expect(board.unassigned).toBe(2);
    expect(board.first?.title).toBe('Ransomware Attempt');
    expect(board.headline).toBe('4 open cases, 2 with no owner. Start with Ransomware Attempt.');
    expect(board.top.map((x) => x.id)).toEqual(['1', '2', '5']);
  });
  it('reads naturally for one case, for all owned, and for none', () => {
    expect(actNow([c({ title: 'Only', assignee: 'a@x.com' })]).headline).toBe('1 open case, all with an owner. Start with Only.');
    expect(actNow([]).headline).toBe('No open cases. Nothing needs you right now.');
    expect(actNow([c({ status: 'resolved' })]).first).toBeNull();
  });
});
