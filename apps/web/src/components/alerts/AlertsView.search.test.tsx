import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ list: vi.fn(async () => ({ connectors: [] })), listChildren: vi.fn(async () => []) }));
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  connectorsApi: { list: api.list },
  msspApi: { listChildren: api.listChildren },
}));

import { FiltersBar } from './AlertsView';

function show(onChange = vi.fn(), filters = { page: 3, pageSize: 25 } as Record<string, unknown>) {
  render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <FiltersBar filters={filters} onChange={onChange} total={10} />
    </SWRConfig>
  );
  return onChange;
}

afterEach(() => vi.useRealTimers());

describe('alerts search box', () => {
  it('waits a moment after typing, then filters by the text and goes back to page 1', async () => {
    vi.useFakeTimers();
    const onChange = show();
    fireEvent.change(screen.getByLabelText('Search alerts'), { target: { value: ' LPT-83Y6LL3 ' } });
    expect(onChange).not.toHaveBeenCalled();
    await act(async () => {
      vi.advanceTimersByTime(400);
    });
    expect(onChange).toHaveBeenCalledWith({ page: 1, pageSize: 25, search: 'LPT-83Y6LL3' });
  });

  it('searches straight away on Enter', () => {
    const onChange = show();
    const box = screen.getByLabelText('Search alerts');
    fireEvent.change(box, { target: { value: 'disk' } });
    fireEvent.keyDown(box, { key: 'Enter' });
    expect(onChange).toHaveBeenCalledWith({ page: 1, pageSize: 25, search: 'disk' });
  });

  it('shows the active search in the box, and clearing it removes the filter', async () => {
    vi.useFakeTimers();
    const onChange = show(vi.fn(), { page: 1, pageSize: 25, search: 'disk' });
    const box = screen.getByLabelText('Search alerts') as HTMLInputElement;
    expect(box.value).toBe('disk');
    fireEvent.change(box, { target: { value: '' } });
    await act(async () => {
      vi.advanceTimersByTime(400);
    });
    expect(onChange).toHaveBeenCalledWith({ page: 1, pageSize: 25, search: undefined });
  });
});

describe('device filter', () => {
  it('shows the machine being filtered on, and its chip removes the filter and goes back to page 1', () => {
    const onChange = show(vi.fn(), { page: 3, pageSize: 25, device: 'HCC-FS01' });
    fireEvent.click(screen.getByRole('button', { name: 'Remove device filter HCC-FS01' }));
    expect(onChange).toHaveBeenCalledWith({ page: 1, pageSize: 25, device: undefined });
  });

  it('has no device chip when no device is chosen', () => {
    show();
    expect(screen.queryByText(/^Device:/)).not.toBeInTheDocument();
  });
});
