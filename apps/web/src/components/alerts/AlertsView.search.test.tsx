import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ list: vi.fn(async () => ({ connectors: [] })), listChildren: vi.fn(async () => []) }));
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  connectorsApi: { list: api.list },
  msspApi: { listChildren: api.listChildren },
}));

import { AlertRow, FiltersBar } from './AlertsView';
import type { Alert } from '@/lib/api';

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

describe('alert row device', () => {
  const base = { id: 'a1', title: 'Low disk', description: '', severity: 'high', status: 'new', source: 'ninjaone', tenantId: 't', riskScore: 1, createdAt: '2026-10-13T00:00:00Z', updatedAt: '2026-10-13T00:00:00Z' } as Alert;

  it('shows the machine name next to the source', () => {
    render(<AlertRow alert={{ ...base, device: 'HCC-FS01' }} selected={false} onSelect={vi.fn()} />);
    expect(screen.getByTestId('alert-device')).toHaveTextContent('HCC-FS01');
  });

  it('shows no device marker when the alert names no machine', () => {
    render(<AlertRow alert={base} selected={false} onSelect={vi.fn()} />);
    expect(screen.queryByTestId('alert-device')).not.toBeInTheDocument();
  });
});

describe('status tabs', () => {
  it('lists Open all first and All status last, and marks the active one', () => {
    show(vi.fn(), { page: 1, pageSize: 25, status: 'open' });
    const labels = ['Open all', 'new', 'investigating', 'resolved', 'false positive', 'All status'];
    const buttons = labels.map((l) => screen.getByRole('button', { name: new RegExp(`^${l}$`, 'i') }));
    for (let i = 1; i < buttons.length; i++) expect(buttons[i - 1].compareDocumentPosition(buttons[i]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(buttons[0].className).toContain('bg-gray-700');
    expect(buttons[5].className).not.toContain('bg-gray-700');
  });

  it('asks for status open, for one named status, or for no status filter at all', () => {
    const onChange = show(vi.fn(), { page: 2, pageSize: 25, status: 'resolved' });
    fireEvent.click(screen.getByRole('button', { name: /^Open all$/i }));
    expect(onChange).toHaveBeenLastCalledWith({ page: 1, pageSize: 25, status: 'open' });
    fireEvent.click(screen.getByRole('button', { name: /^All status$/i }));
    expect(onChange).toHaveBeenLastCalledWith({ page: 1, pageSize: 25, status: undefined });
    fireEvent.click(screen.getByRole('button', { name: /^new$/i }));
    expect(onChange).toHaveBeenLastCalledWith({ page: 1, pageSize: 25, status: 'new' });
  });
});

describe('filters from the address', () => {
  it('starts on Open all, narrows to a device, and honours status=all', async () => {
    const { filtersFromUrl } = await import('./AlertsView');
    expect(filtersFromUrl(new URLSearchParams(''))).toEqual({ page: 1, pageSize: 25, status: 'open' });
    expect(filtersFromUrl(new URLSearchParams('device=Mac&status=all'))).toEqual({ page: 1, pageSize: 25, device: 'Mac' });
    expect(filtersFromUrl(new URLSearchParams('status=resolved'))).toEqual({ page: 1, pageSize: 25, status: 'resolved' });
    expect(filtersFromUrl(new URLSearchParams('status=bogus'))).toEqual({ page: 1, pageSize: 25, status: 'open' });
  });
});
