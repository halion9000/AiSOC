import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ list: vi.fn(), decide: vi.fn(), promote: vi.fn() }));
const toast = vi.hoisted(() => Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }));
vi.mock('@/lib/api', () => ({ detectionProposalsApi: api }));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: toast }));
vi.mock('next/link', () => ({ default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => <a href={href} {...rest}>{children}</a> }));

import { DetectionProposalsView } from './DetectionProposalsView';

const proposal = (over: Record<string, unknown> = {}) => ({
  id: 'p1',
  name: 'Impossible travel v2',
  description: 'Tighter window',
  rule_language: 'sigma',
  severity: 'high',
  status: 'proposed',
  updated_at: new Date(Date.now() - 3600_000).toISOString(),
  mitre_techniques: ['T1078', 'T1110'],
  eval_result: {},
  github_pr_url: null,
  ...over,
});
const evalResult = (over: Record<string, unknown> = {}) => ({ candidate: { mitre_accuracy: 0.912 }, baseline: { mitre_accuracy: 0.93 }, drop_pp: 1.8, regressed: true, passed: false, ...over });

function renderIt() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <DetectionProposalsView />
    </SWRConfig>,
  );
}

beforeEach(() => {
  api.list.mockReset();
  api.decide.mockReset().mockResolvedValue({});
  api.promote.mockReset().mockResolvedValue({});
  toast.success.mockReset();
  toast.error.mockReset();
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});

const card = (name: string) => screen.getByText(name).closest('li') as HTMLElement;

describe('DetectionProposalsView', () => {
  it('says there is nothing when there are no proposals', async () => {
    api.list.mockResolvedValue([]);
    renderIt();
    expect(await screen.findByText('No proposals yet')).toBeInTheDocument();
  });

  it('shows the error with a Retry that asks again', async () => {
    api.list.mockRejectedValueOnce(new Error('down')).mockResolvedValueOnce([proposal()]);
    renderIt();
    expect(await screen.findByText("Couldn't load proposals")).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /retry|try again/i }));
    expect(await screen.findByText('Impossible travel v2')).toBeInTheDocument();
  });

  it('shows each proposal: status, name, language and severity, description, age and MITRE techniques', async () => {
    api.list.mockResolvedValue([proposal()]);
    renderIt();
    const c = await screen.findByText('Impossible travel v2').then(() => card('Impossible travel v2'));
    expect(within(c).getByText('Proposed')).toBeInTheDocument();
    expect(within(c).getByText('SIGMA · high')).toBeInTheDocument();
    expect(within(c).getByText('Tighter window')).toBeInTheDocument();
    expect(within(c).getByText(/Updated about 1 hour ago/)).toBeInTheDocument();
    expect(within(c).getByText('MITRE: T1078, T1110')).toBeInTheDocument();
  });

  it('asks for all proposals at first and for one status when that button is chosen', async () => {
    api.list.mockResolvedValue([proposal()]);
    renderIt();
    await screen.findByText('Impossible travel v2');
    expect(api.list).toHaveBeenCalledWith(undefined);
    await userEvent.click(screen.getByRole('button', { name: 'Eval passed' }));
    await waitFor(() => expect(api.list).toHaveBeenCalledWith({ status: 'eval_passed' }));
  });

  it('shows the eval comparison with candidate and baseline accuracy and the gate result', async () => {
    api.list.mockResolvedValue([proposal({ status: 'eval_failed', eval_result: evalResult() })]);
    renderIt();
    const c = await screen.findByText('Impossible travel v2').then(() => card('Impossible travel v2'));
    expect((within(c).getByText('Candidate MITRE').nextElementSibling as HTMLElement).textContent).toBe('91.2%');
    expect((within(c).getByText('Baseline MITRE').nextElementSibling as HTMLElement).textContent).toBe('93.0%');
    expect(within(c).getByText('FAIL')).toBeInTheDocument();
  });

  it('shows the regression in percentage points as the server gives it (1.8 means 1.8 points, not 180)', async () => {
    api.list.mockResolvedValue([proposal({ status: 'eval_failed', eval_result: evalResult({ drop_pp: 1.8 }) })]);
    renderIt();
    const c = await screen.findByText('Impossible travel v2').then(() => card('Impossible travel v2'));
    expect((within(c).getByText('Regression').nextElementSibling as HTMLElement).textContent).toBe('1.80pp');
  });

  it('shows a dash for numbers the eval did not return, and a passing gate in green', async () => {
    api.list.mockResolvedValue([proposal({ status: 'eval_passed', eval_result: { candidate: {}, baseline: {}, passed: true, regressed: false } })]);
    renderIt();
    const c = await screen.findByText('Impossible travel v2').then(() => card('Impossible travel v2'));
    expect(within(c).getAllByText('—')).toHaveLength(3);
    expect(within(c).getByText('PASS').className).toContain('text-emerald-300');
  });

  it('shows no eval box for a proposal that has not been evaluated', async () => {
    api.list.mockResolvedValue([proposal()]);
    renderIt();
    await screen.findByText('Impossible travel v2');
    expect(screen.queryByText('Candidate MITRE')).toBeNull();
  });

  it('offers Approve and Reject only while it is in review or has passed its eval', async () => {
    api.list.mockResolvedValue([
      proposal({ id: 'a', name: 'A', status: 'proposed' }),
      proposal({ id: 'b', name: 'B', status: 'in_review' }),
      proposal({ id: 'c', name: 'C', status: 'eval_passed' }),
      proposal({ id: 'd', name: 'D', status: 'eval_failed' }),
      proposal({ id: 'e', name: 'E', status: 'promoted' }),
    ]);
    renderIt();
    await screen.findByText('A');
    for (const [name, shown] of [['A', false], ['B', true], ['C', true], ['D', false], ['E', false]] as const) {
      expect(within(card(name)).queryByRole('button', { name: 'Approve' }) !== null, name).toBe(shown);
    }
  });

  it('Approve and Reject send the decision, say so, and reload the list', async () => {
    api.list.mockResolvedValue([proposal({ status: 'eval_passed' })]);
    renderIt();
    await userEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(api.decide).toHaveBeenCalledWith('p1', { decision: 'approve' });
    expect(toast.success).toHaveBeenCalledWith('Approved');
    await userEvent.click(screen.getByRole('button', { name: 'Reject' }));
    expect(api.decide).toHaveBeenLastCalledWith('p1', { decision: 'reject' });
    expect(toast.success).toHaveBeenLastCalledWith('Rejected');
    await waitFor(() => expect(api.list.mock.calls.length).toBeGreaterThan(1));
  });

  it('a decision that fails is reported, not shown as done', async () => {
    api.decide.mockRejectedValue(new Error('403'));
    api.list.mockResolvedValue([proposal({ status: 'in_review' })]);
    renderIt();
    await userEvent.click(await screen.findByRole('button', { name: 'Reject' }));
    expect(toast.error).toHaveBeenCalledWith('Could not reject proposal');
    expect(toast.success).not.toHaveBeenCalled();
  });

  it('Promote is offered only once approved, and says when the gate blocks it', async () => {
    api.list.mockResolvedValue([proposal({ status: 'approved' }), proposal({ id: 'q', name: 'Not yet', status: 'eval_passed' })]);
    renderIt();
    await screen.findByText('Not yet');
    expect(within(card('Not yet')).queryByRole('button', { name: 'Promote → Active' })).toBeNull();
    api.promote.mockRejectedValueOnce(new Error('gate'));
    await userEvent.click(screen.getByRole('button', { name: 'Promote → Active' }));
    expect(toast.error).toHaveBeenCalledWith('Promote blocked — check eval gate');
    await userEvent.click(screen.getByRole('button', { name: 'Promote → Active' }));
    expect(api.promote).toHaveBeenCalledWith('p1');
    expect(toast.success).toHaveBeenCalledWith('Promoted to active rule');
  });

  it('when promoting opens a pull request the message links to it; an existing one is linked on the card', async () => {
    api.promote.mockResolvedValue({ github_pr_url: 'https://github.com/x/y/pull/9' });
    api.list.mockResolvedValue([proposal({ status: 'approved', github_pr_url: 'https://github.com/x/y/pull/7' })]);
    renderIt();
    await userEvent.click(await screen.findByRole('button', { name: 'Promote → Active' }));
    const message = toast.success.mock.calls[0][0] as React.ReactElement;
    expect(message).toBeTruthy();
    const { container } = render(<>{message}</>);
    const link = container.querySelector('a') as HTMLAnchorElement;
    expect(link.href).toBe('https://github.com/x/y/pull/9');
    expect(link.rel).toContain('noopener');
    const existing = screen.getByRole('link', { name: /View PR/ });
    expect(existing).toHaveAttribute('href', 'https://github.com/x/y/pull/7');
    expect(existing).toHaveAttribute('target', '_blank');
  });

  it('links back to the active rules', async () => {
    api.list.mockResolvedValue([]);
    renderIt();
    expect(screen.getByRole('link', { name: /Active rules/ })).toHaveAttribute('href', '/detection');
  });
});
