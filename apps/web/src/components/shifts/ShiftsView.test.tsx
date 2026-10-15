import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { SWRConfig } from 'swr';

vi.mock('@/lib/api', () => ({
  shiftsApi: {
    handoffItems: async () => [
      { id: '1', priority: 'info', title: 'Disk free space low', type: 'alert', status: 'new', assigned_to: 'unassigned', notes: null },
      { id: '2', priority: 'weird', title: 'Odd severity', type: 'alert', status: 'new', assigned_to: 'unassigned', notes: null },
      { id: '3', priority: 'critical', title: 'RDP exposed', type: 'case', status: 'open', assigned_to: 'x', notes: null },
    ],
  },
}));

import { ShiftsView, priorityStyle } from './ShiftsView';

describe('ShiftsView', () => {
  it('renders info and unknown-severity alerts instead of crashing the page', async () => {
    render(
      <SWRConfig value={{ provider: () => new Map() }}>
        <ShiftsView />
      </SWRConfig>,
    );
    expect(await screen.findByText('Disk free space low')).toBeTruthy();
    expect(screen.getByText('Odd severity')).toBeTruthy();
    expect(screen.getByText('RDP exposed')).toBeTruthy();
  });

  it('has a style for any priority string', () => {
    expect(priorityStyle('info').label).toBe('Info');
    expect(priorityStyle('nonsense').label).toBe('Info');
    expect(priorityStyle('critical').label).toBe('Critical');
  });
});
