import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ queue: vi.fn(), stats: vi.fn(), get: vi.fn() }));
vi.mock('@/lib/api', () => ({ entityRiskApi: api }));
// The tenant picker's data (GET /tenants/selectable). No data = no picker, which is what an ordinary user gets.
const picker = vi.hoisted(() => ({ value: { data: undefined } as { data?: unknown } }));
vi.mock('@/hooks/useSelectableTenants', () => ({ useSelectableTenants: () => picker.value }));

import { EntityRiskQueue } from './EntityRiskQueue';

const stamp = '2026-10-08T01:00:00Z';
const record = (value: string, score: number, promoted: boolean) => ({
  tenant_id: 't1', entity_type: 'user', entity_value: value, score, display_score: score, threshold: 80, promoted, promoted_incident_id: null,
  last_seen: stamp, first_seen: stamp, contributions: [], severity_histogram: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, alert_count: 3,
});
const stats = { tenant_id: 't1', threshold: 80, total: 2, promoted: 1, bands: { critical: 1, high: 0, medium: 1, low: 0 }, alert_count: 40 };

function renderQueue() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <EntityRiskQueue />
    </SWRConfig>,
  );
}
/** The text of the stat tile with this label, e.g. "2Active entities". */
const tile = (label: string) => screen.getByText(label).parentElement!.textContent ?? '';

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  picker.value = { data: undefined };
  api.queue.mockResolvedValue({ tenant_id: 't1', threshold: 80, entities: [record('alice', 91, true), record('bob', 40, false)] });
  api.stats.mockResolvedValue(stats);
});

// When the queue could not be loaded this screen said "Fusion service unreachable, showing demo entity queue so you can explore Risk-Based Alerting" (no demo queue exists), and then fell through
// to "No entities are currently being tracked." (a failure presented as an empty queue), with every tile computed from nothing: 0 entities, 0 promoted, 0 alerts, and an alert:incident ratio of 0:0 below the bar.
describe('when the queue loads', () => {
  it('shows the real entities and the real figures, with no demo wording', async () => {
    const { container } = renderQueue();
    expect(await screen.findByText('alice')).toBeInTheDocument();
    expect(screen.getByText('bob')).toBeInTheDocument();
    await waitFor(() => expect(tile('Active entities')).toContain('2'));
    expect(tile('Contributing alerts')).toContain('40');
    expect(container.textContent).not.toMatch(/demo/i);
  });

  it('still says so when there genuinely are no entities, and for the promoted-only filter', async () => {
    api.queue.mockResolvedValue({ tenant_id: 't1', threshold: 80, entities: [] });
    api.stats.mockResolvedValue({ ...stats, total: 0, promoted: 0, alert_count: 0 });
    renderQueue();
    expect(await screen.findByText('No entities are currently being tracked.')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Promoted only' }));
    expect(await screen.findByText('No entities have crossed the promotion threshold yet.')).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load the entity queue")).not.toBeInTheDocument();
  });
});

describe('when the queue cannot be loaded', () => {
  beforeEach(() => {
    api.queue.mockRejectedValue(new Error('HTTP 503'));
    api.stats.mockRejectedValue(new Error('HTTP 503'));
  });

  it('says so with the reason and a working Retry, and does not claim nothing is being tracked', async () => {
    const { container } = renderQueue();
    expect(await screen.findByText("Couldn't load the entity queue")).toBeInTheDocument();
    expect(screen.getByText(/HTTP 503/)).toBeInTheDocument();
    expect(screen.queryByText('No entities are currently being tracked.')).not.toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo/i);

    api.queue.mockResolvedValue({ tenant_id: 't1', threshold: 80, entities: [record('alice', 91, true)] });
    api.stats.mockResolvedValue(stats);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('alice')).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load the entity queue")).not.toBeInTheDocument();
  });

  it('shows dashes, never invented zeros or a 0:0 ratio, for the figures it does not know', async () => {
    renderQueue();
    await screen.findByText("Couldn't load the entity queue");
    for (const label of ['Active entities', 'Promoted', 'Contributing alerts', 'Alert \u2192 Incident']) {
      expect(tile(label)).toContain('\u2014');
      expect(tile(label)).not.toMatch(/(^|\D)0(\D|$)/);
    }
    expect(screen.queryByText('0:0')).not.toBeInTheDocument();
    expect(screen.getByText(/\u2014 shown/)).toBeInTheDocument();
  });

  it('still shows the stats figures when only the queue failed (they come from a separate call and are real)', async () => {
    api.stats.mockResolvedValue(stats);
    renderQueue();
    await screen.findByText("Couldn't load the entity queue");
    await waitFor(() => expect(tile('Active entities')).toContain('2'));
    expect(tile('Contributing alerts')).toContain('40');
  });
});

// The console used to send a BUILD-TIME constant as the tenant ('default' on a standard build: not a UUID, a 422; some other tenant's id elsewhere: a 403), so this page only worked on single-tenant installs. It now names NO tenant by default (the server resolves the
// caller's own), and names one only when a user who may look at other tenants picks it.
const holder = { own_tenant_id: 't1', can_select_other_tenants: true, tenants: [{ id: 't1', name: 'Home MSP', slug: 'home' }, { id: 'tenant-b', name: 'Bravo Corp', slug: 'bravo' }] };
const tenantPicker = () => screen.getByRole('combobox', { name: /Tenant/ });
const askedFor = (mock: ReturnType<typeof vi.fn>, pick: (call: unknown[]) => unknown) => mock.mock.calls.map(pick);

describe('which tenant it asks about', () => {
  it('names NO tenant by default: the server resolves the caller\'s own', async () => {
    renderQueue();
    await screen.findByText('alice');
    expect(api.queue).toHaveBeenCalledWith({ limit: 50, promotedOnly: false, tenantId: undefined });
    expect(api.stats).toHaveBeenCalledWith(undefined);
    expect(askedFor(api.queue, (c) => (c[0] as { tenantId?: string }).tenantId).every((t) => t === undefined)).toBe(true);
  });

  it('offers no tenant picker to a user who may not look at other tenants', async () => {
    picker.value = { data: { ...holder, can_select_other_tenants: false } };
    renderQueue();
    await screen.findByText('alice');
    expect(screen.queryByRole('combobox', { name: /Tenant/ })).not.toBeInTheDocument();
  });

  it('asks for exactly the tenant that was picked, for the queue AND the stats, and shows that tenant\'s entities', async () => {
    picker.value = { data: holder };
    api.queue.mockImplementation(async (p: { tenantId?: string }) => ({ tenant_id: p.tenantId ?? 't1', threshold: 80, entities: [record(p.tenantId ? 'carol' : 'alice', 70, false)] }));
    renderQueue();
    await screen.findByText('alice');
    await userEvent.setup().selectOptions(tenantPicker(), 'Bravo Corp');
    expect(await screen.findByText('carol')).toBeInTheDocument();
    expect(api.queue).toHaveBeenLastCalledWith({ limit: 50, promotedOnly: false, tenantId: 'tenant-b' });
    expect(api.stats).toHaveBeenLastCalledWith('tenant-b');
    expect(screen.getByRole('status')).toHaveTextContent("Viewing Bravo Corp's data (read-only).");
  });

  it('NEVER shows one tenant\'s entities while the other tenant\'s are still loading', async () => {
    picker.value = { data: holder };
    let release: (v: unknown) => void = () => undefined;
    api.queue.mockImplementation((p: { tenantId?: string }) =>
      p.tenantId ? new Promise((resolve) => { release = resolve; }) : Promise.resolve({ tenant_id: 't1', threshold: 80, entities: [record('alice', 91, true)] }));
    renderQueue();
    await screen.findByText('alice');
    await userEvent.setup().selectOptions(tenantPicker(), 'Bravo Corp');
    await waitFor(() => expect(api.queue).toHaveBeenLastCalledWith({ limit: 50, promotedOnly: false, tenantId: 'tenant-b' }));
    expect(screen.queryByText('alice')).not.toBeInTheDocument(); // tenant 1's entity must not sit under a "Viewing Bravo Corp" banner
    release({ tenant_id: 'tenant-b', threshold: 80, entities: [record('carol', 60, false)] });
    expect(await screen.findByText('carol')).toBeInTheDocument();
  });

  it('going back to the caller\'s own tenant names no tenant again', async () => {
    picker.value = { data: holder };
    renderQueue();
    await screen.findByText('alice');
    const user = userEvent.setup();
    await user.selectOptions(tenantPicker(), 'Bravo Corp');
    await waitFor(() => expect(api.queue).toHaveBeenLastCalledWith({ limit: 50, promotedOnly: false, tenantId: 'tenant-b' }));
    await user.click(screen.getByRole('button', { name: 'Back to my tenant' }));
    await waitFor(() => expect(api.queue).toHaveBeenLastCalledWith({ limit: 50, promotedOnly: false, tenantId: undefined }));
    expect(api.stats).toHaveBeenLastCalledWith(undefined);
  });

  it('the detail drawer asks about the same tenant as the list', async () => {
    picker.value = { data: holder };
    api.get.mockResolvedValue(record('alice', 91, true));
    renderQueue();
    const user = userEvent.setup();
    await user.click(await screen.findByText('alice'));
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('user', 'alice', undefined));
    await user.click(screen.getByRole('button', { name: /close/i }));
    await user.selectOptions(tenantPicker(), 'Bravo Corp');
    await user.click(await screen.findByText('alice'));
    await waitFor(() => expect(api.get).toHaveBeenLastCalledWith('user', 'alice', 'tenant-b'));
  });

  it('the drawer NEVER shows one tenant\'s detail for an entity of the same name in another tenant (cached detail must not cross)', async () => {
    // "admin", a shared IP: the same entity value can exist in two tenants. Tenant 1's detail says score 99; tenant B's list says 55 and its detail is still loading.
    picker.value = { data: holder };
    api.queue.mockImplementation(async (p: { tenantId?: string }) => ({ tenant_id: p.tenantId ?? 't1', threshold: 80, entities: [record('alice', p.tenantId ? 55 : 91, false)] }));
    api.get.mockImplementation((_type: string, _value: string, tenantId?: string) => (tenantId ? new Promise(() => undefined) : Promise.resolve(record('alice', 99, true))));
    const { container } = renderQueue();
    const user = userEvent.setup();
    await user.click(await screen.findByText('alice'));
    await waitFor(() => expect(container.textContent).toContain('99')); // tenant 1's own detail is on screen
    await user.click(screen.getByRole('button', { name: /close/i }));
    await user.selectOptions(tenantPicker(), 'Bravo Corp');
    await user.click(await screen.findByText('alice'));
    await waitFor(() => expect(api.get).toHaveBeenLastCalledWith('user', 'alice', 'tenant-b'));
    expect(await screen.findByRole('heading', { name: 'alice' })).toBeInTheDocument();
    expect(container.textContent).not.toContain('99'); // not tenant 1's cached detail under a "Viewing Bravo Corp" banner
  });

  it('changing the tenant closes an open drawer (it belongs to the tenant that was on screen)', async () => {
    picker.value = { data: holder };
    api.get.mockResolvedValue(record('alice', 91, true));
    renderQueue();
    const user = userEvent.setup();
    await user.click(await screen.findByText('alice'));
    expect(await screen.findByRole('heading', { name: 'alice' })).toBeInTheDocument();
    await user.selectOptions(tenantPicker(), 'Bravo Corp');
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'alice' })).not.toBeInTheDocument());
    expect(await screen.findByText('alice')).toBeInTheDocument(); // the row of the new tenant's queue is still there, only the drawer is gone
  });
});
