import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import type { DetectionRule } from '@/lib/api';

const api = vi.hoisted(() => ({ list: vi.fn(), update: vi.fn(), bulkToggle: vi.fn() }));
const toastFn = vi.hoisted(() => vi.fn());
const toastError = vi.hoisted(() => vi.fn());
const toastSuccess = vi.hoisted(() => vi.fn());

vi.mock('@/lib/api', () => ({ __esModule: true, detectionApi: api }));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: Object.assign(toastFn, { error: toastError, success: toastSuccess }) }));
vi.mock('./ContributorLeaderboard', () => ({ ContributorLeaderboard: () => null }));
vi.mock('./MitreRuleHeatmap', () => ({ MitreRuleHeatmap: () => null }));
vi.mock('./ConfidenceTrends', () => ({ ConfidenceTrends: () => null }));
vi.mock('./DriftInbox', () => ({ DriftInbox: () => null }));

import { DetectionsView } from './DetectionsView';

// When the rules API failed, this view set `useFallback = !!error`, which (1) made its real error screen unreachable (that screen required `error && !useFallback`),
// (2) showed a banner claiming "showing curated demo rules" when no rules were shown, and (3) made every rule toggle SKIP the backend call while still toasting "Rule
// enabled" / "Rule disabled", and bulk toggles "N rules disabled (demo)". Because it was just "is there an error", a failed REFRESH while real rules were on screen
// flipped it too: you could "disable" a real detection rule, be told it worked, and nothing had been saved.
const stamp = '2026-10-07T12:00:00Z';
const rule = (over: Partial<DetectionRule> & { id: string; name: string }): DetectionRule => ({ language: 'sigma', body: 'detection: x', enabled: true, severity: 'high', createdAt: stamp, updatedAt: stamp, ...over });
const r1 = rule({ id: 'r1', name: 'Impossible travel', enabled: true });
const r2 = rule({ id: 'r2', name: 'Rare process', enabled: false });

function renderView() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <DetectionsView />
    </SWRConfig>,
  );
}

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  [toastFn, toastError, toastSuccess].forEach((m) => m.mockReset());
  api.list.mockResolvedValue({ rules: [r1, r2], total: 2 });
});

describe('the rule list', () => {
  it('shows the real rules and no demo wording', async () => {
    const { container } = renderView();
    expect(await screen.findByText('Impossible travel')).toBeInTheDocument();
    expect(screen.getByText('Rare process')).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo|curated/i);
  });

  it('shows the real error with a Retry, and no demo claim, when the first load fails', async () => {
    api.list.mockRejectedValueOnce(new Error('503 detection service down'));
    const { container } = renderView();
    expect(await screen.findByText("Couldn't load detection rules")).toBeInTheDocument(); // this screen used to be unreachable
    expect(screen.getByText("The detection service didn't respond.")).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo|curated/i);
    await userEvent.setup().click(screen.getByRole('button', { name: /retry|try again/i }));
    expect(await screen.findByText('Impossible travel')).toBeInTheDocument();
  });
});

describe('toggling a rule', () => {
  it('calls the backend and confirms', async () => {
    api.update.mockResolvedValue({});
    renderView();
    await screen.findByText('Impossible travel');
    await userEvent.setup().click(screen.getAllByRole('switch', { name: 'Disable rule' })[0]);
    await waitFor(() => expect(toastSuccess).toHaveBeenCalledWith('Rule disabled'));
    expect(api.update).toHaveBeenCalledWith('r1', { enabled: false });
  });

  it('says it could not, and confirms nothing, when the backend refuses', async () => {
    api.update.mockRejectedValue(new Error('403'));
    renderView();
    await screen.findByText('Impossible travel');
    await userEvent.setup().click(screen.getAllByRole('switch', { name: 'Disable rule' })[0]);
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Could not update rule'));
    expect(toastSuccess).not.toHaveBeenCalled();
  });

  it('STILL calls the backend after a failed refresh, and says the list may be stale (the dangerous case)', async () => {
    api.list.mockReset();
    api.list.mockResolvedValueOnce({ rules: [r1, r2], total: 2 }).mockRejectedValue(new Error('503 refresh failed'));
    api.update.mockResolvedValue({});
    renderView();
    const user = userEvent.setup();
    await screen.findByText('Impossible travel');

    await user.click(screen.getAllByRole('switch', { name: 'Disable rule' })[0]); // saves, then the re-read FAILS
    await waitFor(() => expect(api.update).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/Couldn.t refresh the detection rules/)).toBeInTheDocument();
    expect(screen.getByText('Impossible travel')).toBeInTheDocument(); // the last-loaded rules are still shown

    // both rules are off now (the first was just disabled), so take the SECOND switch: 'Rare process', now with an error present
    await user.click(screen.getAllByRole('switch', { name: 'Enable rule' })[1]);
    await waitFor(() => expect(api.update).toHaveBeenCalledTimes(2)); // it used to be skipped here
    expect(api.update).toHaveBeenLastCalledWith('r2', { enabled: true });
    await waitFor(() => expect(toastSuccess).toHaveBeenCalledWith('Rule enabled'));
    // and no message of any kind talks about demo data, however it is raised
    const everyToast = [...toastFn.mock.calls, ...toastError.mock.calls, ...toastSuccess.mock.calls].flat().join(' ');
    expect(everyToast).not.toMatch(/demo/i);
  });

  it('does not report success for a toggle the backend refused, even after a failed refresh', async () => {
    api.list.mockReset();
    api.list.mockResolvedValueOnce({ rules: [r1, r2], total: 2 }).mockRejectedValue(new Error('503'));
    api.update.mockResolvedValueOnce({}).mockRejectedValue(new Error('500'));
    renderView();
    const user = userEvent.setup();
    await screen.findByText('Impossible travel');
    await user.click(screen.getAllByRole('switch', { name: 'Disable rule' })[0]);
    await screen.findByText(/Couldn.t refresh the detection rules/);
    toastSuccess.mockClear();
    await user.click(screen.getAllByRole('switch', { name: 'Enable rule' })[1]); // the second rule; the first was just disabled
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Could not update rule'));
    expect(toastSuccess).not.toHaveBeenCalled(); // it used to say "Rule enabled" here without ever calling the backend
  });
});

describe('bulk actions', () => {
  it('calls the backend, and never says "(demo)"', async () => {
    api.bulkToggle.mockResolvedValue({ updated: 1, skipped: [] });
    renderView();
    const user = userEvent.setup();
    await screen.findByText('Impossible travel');
    await user.click(screen.getByLabelText('Select rule Impossible travel'));
    await user.click(screen.getByRole('button', { name: 'Disable' }));
    await waitFor(() => expect(api.bulkToggle).toHaveBeenCalledWith(['r1'], false));
    expect(toastSuccess).toHaveBeenCalledWith('1 rule disabled');
    expect(toastSuccess.mock.calls.flat().join(' ')).not.toMatch(/demo/i);
  });

  it('says it could not when the backend refuses', async () => {
    api.bulkToggle.mockRejectedValue(new Error('500'));
    renderView();
    const user = userEvent.setup();
    await screen.findByText('Impossible travel');
    await user.click(screen.getByLabelText('Select rule Impossible travel'));
    await user.click(screen.getByRole('button', { name: 'Disable' }));
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Could not update rules'));
    expect(toastSuccess).not.toHaveBeenCalled();
  });

  it('still calls the backend for a bulk change after a failed refresh', async () => {
    api.list.mockReset();
    api.list.mockResolvedValueOnce({ rules: [r1, r2], total: 2 }).mockRejectedValue(new Error('503'));
    api.update.mockResolvedValue({});
    api.bulkToggle.mockResolvedValue({ updated: 1, skipped: [] });
    renderView();
    const user = userEvent.setup();
    await screen.findByText('Impossible travel');
    await user.click(screen.getAllByRole('switch', { name: 'Disable rule' })[0]);
    await screen.findByText(/Couldn.t refresh the detection rules/);
    await user.click(screen.getByLabelText('Select rule Rare process'));
    await user.click(screen.getByRole('button', { name: 'Enable' }));
    await waitFor(() => expect(api.bulkToggle).toHaveBeenCalledWith(['r2'], true));
  });
});
