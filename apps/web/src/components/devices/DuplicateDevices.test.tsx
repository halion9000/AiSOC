import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { DeviceRow } from '@/lib/api';

const api = vi.hoisted(() => ({ duplicates: vi.fn(), dismissDuplicate: vi.fn(), mergeDuplicates: vi.fn(), merges: vi.fn(), undoMerge: vi.fn() }));
vi.mock('@/lib/api', () => ({ devicesApi: api }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock('react-hot-toast', () => ({ default: toast }));

import DuplicateDevices, { compareRows, sharedTools, sourceFacts } from './DuplicateDevices';

const NOW = '2026-10-15T15:00:00Z';
const dev = (id: string, hostname: string, vendor: string): DeviceRow =>
  ({ id, tenant_id: 't1', client_name: 'Acme', hostname, serial_number: null, os: 'Windows 11', ip_addresses: [], last_seen: NOW, first_seen: NOW, sources: [{ vendor, name: hostname, last_seen: NOW }], in_master: true }) as unknown as DeviceRow;
const pair = { a: dev('a', 'FRONT-DESK', 'ninjaone'), b: dev('b', 'front-desk', 'addigy') };

beforeEach(() => {
  api.duplicates.mockReset().mockResolvedValue({ items: [pair] });
  api.dismissDuplicate.mockReset().mockResolvedValue(undefined);
  api.mergeDuplicates.mockReset().mockResolvedValue({});
  api.merges.mockReset().mockResolvedValue([]);
  api.undoMerge.mockReset().mockResolvedValue({});
  toast.success.mockReset();
  toast.error.mockReset();
});

/** The two panels start closed: open one the way a person does. */
async function openPairs() {
  await userEvent.setup().click(await screen.findByRole('button', { name: /Possible duplicates/ }));
}
async function openMerges() {
  await userEvent.setup().click(await screen.findByRole('button', { name: /Recent merges/ }));
}

describe('DuplicateDevices', () => {
  it('shows nothing when there are no possible duplicates', async () => {
    api.duplicates.mockResolvedValue({ items: [] });
    const { container } = render(<DuplicateDevices onChanged={vi.fn()} />);
    await waitFor(() => expect(api.duplicates).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it('lists each pair with its client and the tools that report each side', async () => {
    render(<DuplicateDevices onChanged={vi.fn()} />);
    await openPairs();
    expect(await screen.findByRole('region', { name: 'Possible duplicate devices' })).toHaveTextContent('Possible duplicates (1)');
    expect(screen.getByText('FRONT-DESK')).toBeInTheDocument();
    expect(screen.getByText('front-desk')).toBeInTheDocument();
    expect(screen.getByText('Acme')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'NinjaOne' })).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'Addigy' })).toBeInTheDocument();
  });

  it('asks only for the chosen client when one is picked', async () => {
    render(<DuplicateDevices clientId="c1" onChanged={vi.fn()} />);
    await screen.findByRole('region');
    expect(api.duplicates).toHaveBeenCalledWith('c1');
  });

  it('merges into the first, keeping its id, then refreshes the list and the page', async () => {
    const onChanged = vi.fn();
    render(<DuplicateDevices onChanged={onChanged} />);
    await openPairs();
    api.duplicates.mockResolvedValue({ items: [] });
    await userEvent.setup().click(await screen.findByRole('button', { name: /Merge front-desk into the first FRONT-DESK/ }));
    expect(api.mergeDuplicates).toHaveBeenCalledWith('a', 'b');
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    await waitFor(() => expect(screen.queryByRole('region')).not.toBeInTheDocument());
  });

  it('merges into the second the other way round', async () => {
    render(<DuplicateDevices onChanged={vi.fn()} />);
    await openPairs();
    await userEvent.setup().click(await screen.findByRole('button', { name: /Merge FRONT-DESK into the second front-desk/ }));
    expect(api.mergeDuplicates).toHaveBeenCalledWith('b', 'a');
  });

  it('remembers "not a duplicate" for the pair', async () => {
    render(<DuplicateDevices onChanged={vi.fn()} />);
    await openPairs();
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Not a duplicate' }));
    expect(api.dismissDuplicate).toHaveBeenCalledWith('a', 'b');
    expect(api.mergeDuplicates).not.toHaveBeenCalled();
  });

  it('shows the reason when the server refuses, and leaves the pair listed', async () => {
    api.mergeDuplicates.mockRejectedValue(new Error('These have different serial numbers, so they are different machines.'));
    const onChanged = vi.fn();
    render(<DuplicateDevices onChanged={onChanged} />);
    await openPairs();
    await userEvent.setup().click(await screen.findByRole('button', { name: /into the first/ }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('These have different serial numbers, so they are different machines.'));
    expect(onChanged).not.toHaveBeenCalled();
    expect(screen.getByRole('region')).toBeInTheDocument();
  });

  it('shows nothing, not an error, when the list cannot be loaded', async () => {
    api.duplicates.mockRejectedValue(new Error('down'));
    const { container } = render(<DuplicateDevices onChanged={vi.fn()} />);
    await waitFor(() => expect(api.duplicates).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it('opens a side-by-side comparison when the row is clicked, and closes it again', async () => {
    render(<DuplicateDevices onChanged={vi.fn()} />);
    await openPairs();
    const user = userEvent.setup();
    expect(screen.queryByTestId('duplicate-compare')).not.toBeInTheDocument();
    await user.click(await screen.findByText('FRONT-DESK'));
    const compare = await screen.findByTestId('duplicate-compare');
    expect(compare).toHaveTextContent('Serial number');
    expect(compare).toHaveTextContent('Operating system');
    await user.click(screen.getByRole('button', { name: /Hide details of FRONT-DESK/ }));
    expect(screen.queryByTestId('duplicate-compare')).not.toBeInTheDocument();
  });

  it('does not open the comparison when a merge or dismiss button is pressed', async () => {
    render(<DuplicateDevices onChanged={vi.fn()} />);
    await openPairs();
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Not a duplicate' }));
    expect(screen.queryByTestId('duplicate-compare')).not.toBeInTheDocument();
  });
});

describe('what the comparison shows', () => {
  const base = dev('a', 'PC-1', 'ninjaone');
  it('marks a field the same when both sides agree and different when they do not', () => {
    const other = { ...dev('b', 'pc-1', 'addigy'), os: 'macOS', serial_number: 'SN9' } as DeviceRow;
    const rows = Object.fromEntries(compareRows(base, other).map((r) => [r.label, r.same]));
    expect(rows['Name']).toBe(true); // names differ only in case
    expect(rows['Operating system']).toBe(false);
    expect(rows['Serial number']).toBe(false);
    expect(rows['First seen']).toBe(true);
  });

  it('says when a tool already lists both devices, which is a reason to think they are two machines', () => {
    expect(sharedTools(dev('a', 'x', 'ninjaone'), dev('b', 'x', 'ninjaone'))).toEqual(['ninjaone']);
    expect(sharedTools(dev('a', 'x', 'ninjaone'), dev('b', 'x', 'addigy'))).toEqual([]);
  });

  it('lists the tool-reported facts and any problem the tool flagged', () => {
    const d = { ...base, sources: [{ vendor: 'huntress', name: 'PC-1', last_seen: NOW, details: { edr_version: '1.2', last_callback_at: '2026-10-18T10:00:00Z', needs_attention: ['Defender: Unhealthy'] } }] } as unknown as DeviceRow;
    const [s] = sourceFacts(d);
    expect(s.facts).toEqual([['EDR version', '1.2'], ['Last check-in', '2026-10-18 10:00 UTC']]);
    expect(s.attention).toEqual(['Defender: Unhealthy']);
  });
});

describe('undoing a merge', () => {
  const entry = { id: 'm1', client_name: 'Acme', removed_hostname: 'FRONT-DESK', kept_device_id: 'k1', created_at: '2026-10-18T12:00:00Z' };

  it('lists recent merges, even when there are no duplicates left to review, and undoes one then refreshes', async () => {
    api.duplicates.mockResolvedValue({ items: [] });
    api.merges.mockResolvedValueOnce([entry]).mockResolvedValue([]);
    const onChanged = vi.fn();
    render(<DuplicateDevices onChanged={onChanged} />);
    await openMerges();
    const list = await screen.findByTestId('recent-merges');
    expect(list).toHaveTextContent('FRONT-DESK');
    expect(list).toHaveTextContent('Acme');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Undo the merge of FRONT-DESK' }));
    await waitFor(() => expect(api.undoMerge).toHaveBeenCalledWith('m1'));
    expect(toast.success).toHaveBeenCalledWith('Undone: FRONT-DESK is its own device again.');
    expect(onChanged).toHaveBeenCalled();
    await waitFor(() => expect(screen.queryByTestId('recent-merges')).not.toBeInTheDocument());
  });

  it('shows the reason when the API refuses', async () => {
    api.duplicates.mockResolvedValue({ items: [] });
    api.merges.mockResolvedValue([entry]);
    api.undoMerge.mockRejectedValue(new Error('That merge is too old to undo.'));
    render(<DuplicateDevices onChanged={vi.fn()} />);
    await openMerges();
    await userEvent.setup().click(await screen.findByRole('button', { name: /Undo the merge/ }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('That merge is too old to undo.'));
  });

  it('starts with both panels closed, and a heading opens and closes each', async () => {
    render(<DuplicateDevices onChanged={vi.fn()} />);
    const pairsToggle = await screen.findByRole('button', { name: /Possible duplicates/ });
    expect(pairsToggle).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('button', { name: 'Not a duplicate' })).toBeNull();
    const user = userEvent.setup();
    await user.click(pairsToggle);
    expect(pairsToggle).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('button', { name: 'Not a duplicate' })).toBeInTheDocument();
    await user.click(pairsToggle);
    expect(screen.queryByRole('button', { name: 'Not a duplicate' })).toBeNull();
  });

  it('is quiet when there is nothing to undo or the list cannot be read', async () => {
    api.duplicates.mockResolvedValue({ items: [] });
    api.merges.mockRejectedValue(new Error('down'));
    const { container } = render(<DuplicateDevices onChanged={vi.fn()} />);
    await waitFor(() => expect(api.merges).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });
});
