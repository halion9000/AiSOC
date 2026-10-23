import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const scriptOptions = vi.hoisted(() => vi.fn());
const runScriptBulk = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ alertsApi: { scriptOptions: (...a: unknown[]) => scriptOptions(...a), runScriptBulk: (...a: unknown[]) => runScriptBulk(...a) } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import BulkScriptBar, { bulkRunSummary } from './BulkScriptBar';

const plan = {
  batch_id: null,
  preview: true,
  script_name: 'Disk Space Scan',
  runs_at_once: false,
  queued: 2,
  skipped: 1,
  items: [
    { alert_id: 'a', device: 'PC-01', outcome: 'queued', reason: null, request_id: null },
    { alert_id: 'b', device: 'PC-02', outcome: 'queued', reason: null, request_id: null },
    { alert_id: 'c', device: null, outcome: 'skipped', reason: 'This alert does not name a machine.', request_id: null },
  ],
};

beforeEach(() => {
  [scriptOptions, runScriptBulk].forEach((m) => m.mockReset());
  scriptOptions.mockResolvedValue({ scripts: [{ id: 7, name: 'Disk Space Scan', one_click: false }], device: 'PC-01', tickets: [], case_id: null, case_number: null, blocked: null, suggested_script_id: null });
});

describe('BulkScriptBar', () => {
  it('shows nothing when nothing is selected', () => {
    const { container } = render(<BulkScriptBar alertIds={[]} onDone={() => {}} />);
    expect(container.textContent).toBe('');
  });

  it('previews first (queues nothing), then ONE confirm queues the batch', async () => {
    runScriptBulk.mockResolvedValueOnce(plan).mockResolvedValueOnce({ ...plan, preview: false, batch_id: 'b'.repeat(32) });
    const onDone = vi.fn();
    const user = userEvent.setup();
    render(<BulkScriptBar alertIds={['a', 'b', 'c']} onDone={onDone} />);
    await user.click(screen.getByText('Run script on these machines'));
    await user.click(await screen.findByText('See which machines'));
    expect((await screen.findByTestId('bulk-script-plan')).textContent).toContain('PC-02');
    expect(runScriptBulk).toHaveBeenCalledTimes(1);
    expect(runScriptBulk.mock.calls[0][0]).toEqual({ script_id: 7, alert_ids: ['a', 'b', 'c'], preview: true });
    await user.click(screen.getByText('Confirm: run on 2 machines'));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(runScriptBulk.mock.calls[1][0]).toEqual({ script_id: 7, alert_ids: ['a', 'b', 'c'], preview: false });
  });

  it('says why when CORE has shared no scripts', async () => {
    scriptOptions.mockResolvedValue({ scripts: [], device: null, tickets: [], case_id: null, case_number: null, blocked: 'CORE has not shared any scripts.' });
    const user = userEvent.setup();
    render(<BulkScriptBar alertIds={['a']} onDone={() => {}} />);
    await user.click(screen.getByText('Run script on these machines'));
    expect((await screen.findByRole('alert')).textContent).toContain('CORE has not shared any scripts');
  });

  it('summarises how many machines and what is left out', () => {
    expect(bulkRunSummary(plan as never)).toContain('2 machines');
    expect(bulkRunSummary(plan as never)).toContain('1 left out');
  });

  it('shows an API failure instead of swallowing it, and leaves nothing half-done', async () => {
    runScriptBulk.mockRejectedValueOnce(new Error('The API answered 500'));
    const onDone = vi.fn();
    const user = userEvent.setup();
    render(<BulkScriptBar alertIds={['a']} onDone={onDone} />);
    await user.click(screen.getByText('Run script on these machines'));
    await user.click(await screen.findByText('See which machines'));
    expect((await screen.findByRole('alert')).textContent).toContain('The API answered 500');
    expect(screen.queryByTestId('bulk-script-plan')).toBeNull();
    expect(onDone).not.toHaveBeenCalled();
  });

  it('cannot be confirmed when the preview finds nothing to run', async () => {
    runScriptBulk.mockResolvedValueOnce({ ...plan, queued: 0, skipped: 1, items: [{ alert_id: 'a', device: null, outcome: 'skipped', reason: 'This alert does not name a machine.', request_id: null }] });
    const user = userEvent.setup();
    render(<BulkScriptBar alertIds={['a']} onDone={() => {}} />);
    await user.click(screen.getByText('Run script on these machines'));
    await user.click(await screen.findByText('See which machines'));
    const confirm = await screen.findByText('Confirm: run on 0 machines');
    expect(confirm.closest('button')).toBeDisabled();
    expect(screen.getByTestId('bulk-script-plan').textContent).toContain('does not name a machine');
  });
});
