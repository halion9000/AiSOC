import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { MarketplaceItem } from './MarketplaceView';

// Uninstalling removes an item from the tenant's enabled set. Reinstalling is one click, but it is still a removal, so the icon button used to act on the first click; it now asks first, naming the item.
const swrCalls = vi.hoisted(() => new Map<string, unknown>());
vi.mock('swr', () => ({
  __esModule: true,
  default: (key: string) => ({ data: swrCalls.get(key), error: undefined, isLoading: false, mutate: vi.fn(async () => undefined) }),
}));

import { MarketplaceView } from './MarketplaceView';

const item = (id: string, name: string): MarketplaceItem => ({ id, type: 'plugin', name, description: 'd', version: '1.0.0', author: 'AiSOC Core', tags: [], source: 'core', verified: true, plugin_type: 'action', sdks: ['python'] });
const A = item('cloudflare-waf', 'Cloudflare WAF');
const B = item('okta-enricher', 'Okta Enricher');

beforeEach(() => {
  swrCalls.clear();
  swrCalls.set('/marketplace/index.json', { version: '1', generated: '2026-05-04T00:00:00Z', items: [A, B], stats: { total: 2, playbooks: 0, detections: 0, plugins: 2, verified: 2, community: 0 } });
  swrCalls.set('/api/v1/marketplace/installed', { total: 2, items: [{ type: 'plugin', id: A.id }, { type: 'plugin', id: B.id }] });
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const deletes = (fetchMock: ReturnType<typeof vi.fn>) => (fetchMock.mock.calls as unknown as [string, RequestInit][]).filter((c) => c[1]?.method === 'DELETE');
const stubFetch = (response: () => Promise<Response> = async () => new Response('{}', { status: 200 })) => {
  const fetchMock = vi.fn(async () => response());
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
};

describe('uninstalling a marketplace item', () => {
  it('does NOT uninstall on the first click: it asks, naming the item, and sends nothing', async () => {
    const fetchMock = stubFetch();
    render(<MarketplaceView />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Uninstall Cloudflare WAF' }));
    const dialog = await screen.findByRole('alertdialog', { name: 'Uninstall this item?' });
    expect(dialog).toHaveAccessibleDescription(/Remove "Cloudflare WAF" from this tenant\? It stops being enabled here\. You can install it again/);
    expect(deletes(fetchMock)).toHaveLength(0);
  });

  it('names the item that was chosen, not another', async () => {
    stubFetch();
    render(<MarketplaceView />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Uninstall Okta Enricher' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog).toHaveAccessibleDescription(/"Okta Enricher"/);
    expect(dialog).not.toHaveAccessibleDescription(/Cloudflare/);
  });

  it('sends exactly one DELETE for the chosen item, only after confirming', async () => {
    const fetchMock = stubFetch();
    render(<MarketplaceView />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Uninstall Okta Enricher' }));
    await user.click(await screen.findByRole('button', { name: 'Uninstall' }));
    await waitFor(() => expect(deletes(fetchMock)).toHaveLength(1));
    expect(deletes(fetchMock)[0][0]).toBe('/api/v1/marketplace/install?type=plugin&id=okta-enricher');
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
  });

  it('Cancel sends nothing and closes the dialog', async () => {
    const fetchMock = stubFetch();
    render(<MarketplaceView />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Uninstall Cloudflare WAF' }));
    await user.click(await screen.findByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(deletes(fetchMock)).toHaveLength(0);
  });

  it('Escape sends nothing and closes the dialog', async () => {
    const fetchMock = stubFetch();
    render(<MarketplaceView />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Uninstall Cloudflare WAF' }));
    await screen.findByRole('alertdialog');
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(deletes(fetchMock)).toHaveLength(0);
  });

  it('after cancelling one item, confirming another uninstalls the one chosen THEN', async () => {
    const fetchMock = stubFetch();
    render(<MarketplaceView />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Uninstall Cloudflare WAF' }));
    await user.click(await screen.findByRole('button', { name: 'Cancel' }));
    await user.click(screen.getByRole('button', { name: 'Uninstall Okta Enricher' }));
    await user.click(await screen.findByRole('button', { name: 'Uninstall' }));
    await waitFor(() => expect(deletes(fetchMock)).toHaveLength(1));
    expect(deletes(fetchMock)[0][0]).toContain('id=okta-enricher');
  });

  it('locks the dialog while the request runs, so a second click cannot send a second DELETE', async () => {
    const fetchMock = stubFetch(() => new Promise<Response>(() => undefined));
    render(<MarketplaceView />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Uninstall Cloudflare WAF' }));
    await user.click(await screen.findByRole('button', { name: 'Uninstall' }));
    const working = await screen.findByRole('button', { name: 'Working...' });
    expect(working).toBeDisabled();
    await user.click(working);
    expect(deletes(fetchMock)).toHaveLength(1);
  });

  it('after one uninstall has finished, the next dialog opens ready to use (not stuck on "Working...")', async () => {
    const fetchMock = stubFetch();
    render(<MarketplaceView />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Uninstall Cloudflare WAF' }));
    await user.click(await screen.findByRole('button', { name: 'Uninstall' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: 'Uninstall Okta Enricher' }));
    const confirm = await screen.findByRole('button', { name: 'Uninstall' });
    expect(confirm).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Working...' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeEnabled();
    await user.click(confirm);
    await waitFor(() => expect(deletes(fetchMock)).toHaveLength(2));
    expect(deletes(fetchMock)[1][0]).toContain('id=okta-enricher');
  });

  it('a failed uninstall closes the dialog and keeps the item installed, showing the error', async () => {
    stubFetch(async () => new Response('boom', { status: 500 }));
    render(<MarketplaceView />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Uninstall Cloudflare WAF' }));
    await user.click(await screen.findByRole('button', { name: 'Uninstall' }));
    expect(await screen.findByText(/Could not uninstall cloudflare-waf/)).toBeInTheDocument();
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Uninstall Cloudflare WAF' })).toBeInTheDocument();
  });
});
