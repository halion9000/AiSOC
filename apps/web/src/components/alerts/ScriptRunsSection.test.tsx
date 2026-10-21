import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SWRConfig } from 'swr';

const scriptRuns = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ alertsApi: { scriptRuns } }));

import { ScriptRunsSection } from './ScriptRunsSection';

const show = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <ScriptRunsSection alertId="a1" />
    </SWRConfig>,
  );
const run = (over: Record<string, unknown> = {}) => ({ id: 'r1', script_name: 'Disk Space Scan', device: 'PC-01', ticket_id: '553688', new_ticket: false, status: 'done', result_message: 'Started.', created_at: new Date().toISOString(), finished_at: null, ...over });

beforeEach(() => scriptRuns.mockReset());

describe('ScriptRunsSection', () => {
  it('lists each script asked for, with the machine, ticket and what CORE said', async () => {
    scriptRuns.mockResolvedValue([run(), run({ id: 'r2', script_name: 'Restart Spooler', status: 'failed', ticket_id: null, new_ticket: true, result_message: 'No ticket was opened, so nothing was run: no client' })]);
    show();
    const box = await screen.findByTestId('script-runs');
    expect(box).toHaveTextContent('Disk Space Scan');
    expect(box).toHaveTextContent('PC-01');
    expect(box).toHaveTextContent('Sent to CORE · ticket 553688');
    expect(box).toHaveTextContent('Did not run · new ticket');
    expect(box).toHaveTextContent('nothing was run: no client');
  });

  it('shows nothing when no script was asked for', async () => {
    scriptRuns.mockResolvedValue([]);
    show();
    await Promise.resolve();
    expect(screen.queryByTestId('script-runs')).not.toBeInTheDocument();
  });
});
