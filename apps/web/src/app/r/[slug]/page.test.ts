import { beforeEach, describe, expect, it, vi } from 'vitest';

const fetchPublicReplay = vi.hoisted(() => vi.fn());
vi.mock('../../../lib/replay', () => ({ fetchPublicReplay }));
vi.mock('../../../lib/site', () => ({ getPublicSiteUrl: () => 'https://acorn.example.test' }));
vi.mock('next/navigation', () => ({ notFound: () => { throw new Error('NEXT_NOT_FOUND'); } }));
vi.mock('next/link', () => ({ default: () => null }));
vi.mock('./ReplayPlayer', () => ({ ReplayPlayer: () => null }));

import { generateMetadata } from './page';

beforeEach(() => fetchPublicReplay.mockReset());

describe('a public replay page', () => {
  it('is titled with the A.C.O.R.N name, with the verdict, time and steps in its description', async () => {
    fetchPublicReplay.mockResolvedValue({ title: 'Phishing triage', snapshot: { verdict: 'true_positive', elapsedMs: 12000, stepCount: 7, toolCallCount: 4 } });
    const m = await generateMetadata({ params: Promise.resolve({ slug: 'abc' }) });
    expect(m.title).toBe('Phishing triage · A.C.O.R.N investigation replay');
    expect(String(m.description)).toContain('Verdict: true positive');
    expect(String(m.description)).toContain('12s across 7 steps and 4 tool calls');
    expect(m.alternates?.canonical).toBe('https://acorn.example.test/r/abc');
    expect(JSON.stringify(m)).not.toMatch(/AiSOC/);
  });
  it('says the replay was not found, under the same name', async () => {
    fetchPublicReplay.mockResolvedValue(null);
    expect((await generateMetadata({ params: Promise.resolve({ slug: 'nope' }) })).title).toBe('Replay not found · A.C.O.R.N');
  });
});
