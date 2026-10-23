import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ drift: vi.fn() }));
vi.mock('@/lib/api', () => ({ detectionApi: api }));
vi.mock('next/link', () => ({ default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => <a href={href} {...rest}>{children}</a> }));

import { DriftInbox } from './DriftInbox';

const entry = (over: Record<string, unknown> = {}) => ({ ruleId: 'r1', name: 'Impossible travel', enabled: true, severity: 'high', confidence: 41.6, fpRate: 0.425, lastTriggeredAt: null, daysSinceTriggered: null, issues: ['high_fp_rate'], ...over });
const drift = (entries: ReturnType<typeof entry>[]) => ({
  entries,
  summary: {
    total: entries.length,
    highFpRate: entries.filter((e) => (e.issues as string[]).includes('high_fp_rate')).length,
    lowConfidence: entries.filter((e) => (e.issues as string[]).includes('low_confidence')).length,
    stale: entries.filter((e) => (e.issues as string[]).includes('stale')).length,
  },
});

function renderInbox() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <DriftInbox />
    </SWRConfig>,
  );
}

beforeEach(() => api.drift.mockReset());

describe('DriftInbox', () => {
  it('says nothing needs attention when there are no entries', async () => {
    api.drift.mockResolvedValue(drift([]));
    renderInbox();
    expect(await screen.findByText('No rules need attention')).toBeInTheDocument();
  });

  it('shows the error state, and Retry asks again', async () => {
    api.drift.mockRejectedValueOnce(new Error('detection down')).mockResolvedValueOnce(drift([entry()]));
    renderInbox();
    expect(await screen.findByText("Couldn't load drift inbox")).toBeInTheDocument();
    expect(screen.getByText(/detection down/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /retry|try again/i }));
    expect(await screen.findByText('Impossible travel')).toBeInTheDocument();
    expect(api.drift).toHaveBeenCalledTimes(2);
  });

  it('shows each rule with its confidence, false-positive rate, severity and a link to the rule', async () => {
    api.drift.mockResolvedValue(drift([entry()]));
    renderInbox();
    const link = (await screen.findByText('Impossible travel')).closest('a');
    expect(link).toHaveAttribute('href', '/detection/r1');
    expect(within(link as HTMLElement).getByText('42')).toBeInTheDocument();
    expect(within(link as HTMLElement).getByText('42.5%')).toBeInTheDocument();
    expect(within(link as HTMLElement).getByText('high')).toBeInTheDocument();
    expect(within(link as HTMLElement).getByText('never')).toBeInTheDocument();
    expect(within(link as HTMLElement).getByTitle('Enabled')).toBeInTheDocument();
  });

  it('marks a disabled rule, and shows how many days since it last fired', async () => {
    api.drift.mockResolvedValue(drift([entry({ enabled: false, issues: ['stale'], lastTriggeredAt: new Date(Date.now() - 40 * 86400_000).toISOString(), daysSinceTriggered: 40 })]));
    renderInbox();
    await screen.findByText('Impossible travel');
    expect(screen.getByTitle('Disabled')).toBeInTheDocument();
    expect(screen.getByText('(40d)')).toBeInTheDocument();
    expect(screen.queryByText('never')).toBeNull();
  });

  it('counts each bucket and filters to one, saying so when a bucket is empty', async () => {
    api.drift.mockResolvedValue(drift([
      entry({ ruleId: 'a', name: 'Noisy rule', issues: ['high_fp_rate'] }),
      entry({ ruleId: 'b', name: 'Old rule', issues: ['stale', 'low_confidence'] }),
      entry({ ruleId: 'c', name: 'Decayed rule', issues: ['low_confidence'] }),
    ]));
    renderInbox();
    await screen.findByText('Noisy rule');
    expect(screen.getByRole('button', { name: /High FP\s*\(1\)/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Low conf\.\s*\(2\)/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Stale\s*\(1\)/ })).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /Low conf\./ }));
    expect(screen.queryByText('Noisy rule')).toBeNull();
    expect(screen.getByText('Old rule')).toBeInTheDocument();
    expect(screen.getByText('Decayed rule')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /^All$/ }));
    await waitFor(() => expect(screen.getByText('Noisy rule')).toBeInTheDocument());
  });

  it('a rule with several problems shows a badge for each, and an unknown problem is ignored rather than crashing', async () => {
    api.drift.mockResolvedValue(drift([entry({ issues: ['high_fp_rate', 'stale', 'something_new'] })]));
    renderInbox();
    const row = (await screen.findByText('Impossible travel')).closest('a') as HTMLElement;
    expect(within(row).getByText('High FP rate')).toBeInTheDocument();
    expect(within(row).getByText('Stale')).toBeInTheDocument();
    expect(within(row).queryByText(/something_new/)).toBeNull();
  });

  it('a bucket with no rules in it shows an empty message', async () => {
    api.drift.mockResolvedValue(drift([entry({ issues: ['high_fp_rate'] })]));
    renderInbox();
    await screen.findByText('Impossible travel');
    await userEvent.click(screen.getByRole('button', { name: /Stale/ }));
    expect(screen.getByText('No rules in this bucket')).toBeInTheDocument();
  });

  it('the summary strip shows the server totals', async () => {
    api.drift.mockResolvedValue(drift([entry(), entry({ ruleId: 'x', name: 'Other', issues: ['stale'] })]));
    renderInbox();
    await screen.findByText('Other');
    const need = screen.getByText('Need attention').parentElement as HTMLElement;
    expect(within(need).getByText('2')).toBeInTheDocument();
  });
});
