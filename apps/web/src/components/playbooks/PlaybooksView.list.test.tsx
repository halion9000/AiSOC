import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig, mutate } from 'swr';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));
vi.mock('./PlaybooksGallery', () => ({
  PlaybooksGallery: ({ playbooks }: { playbooks: { id: string; name: string }[] }) => (
    <div data-testid="gallery">{playbooks.map((p) => <span key={p.id}>{p.name}</span>)}</div>
  ),
}));
vi.mock('@/components/saved-views/SavedViewsBar', () => ({ SavedViewsBar: () => null }));
vi.mock('./DraftFromPromptDialog', () => ({ DraftFromPromptDialog: () => null }));

import { PlaybooksView } from './PlaybooksView';

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const playbooks = [{ id: 'p1', name: 'Isolate compromised host' }, { id: 'p2', name: 'Enrich IOCs' }];

let listResponse: () => Response | Promise<Response>;

// The default cache on purpose (refreshes use SWR's global mutate), with no de-duplication window so one test cannot be handed another's response.
const view = () => (
  <SWRConfig value={{ dedupingInterval: 0, shouldRetryOnError: false, refreshInterval: 0 }}>
    <PlaybooksView />
  </SWRConfig>
);

beforeEach(async () => {
  await mutate(() => true, undefined, { revalidate: false });
  authFetch.mockReset();
  listResponse = () => json(200, playbooks);
  authFetch.mockImplementation(async (url: string) => (url === '/api/v1/playbooks' ? listResponse() : json(200, [])));
});

// When the playbooks request failed this page said "Agents API unreachable, showing demo playbooks so you can explore the workflow". No demo playbooks exist: it was a false sentence over nothing.
describe('the playbooks list', () => {
  it('shows the real playbooks, with no demo wording and no alert', async () => {
    const { container } = render(view());
    expect(await screen.findByText('Isolate compromised host')).toBeInTheDocument();
    expect(screen.getByText('Enrich IOCs')).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo/i);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('still says a workspace with no playbooks has none', async () => {
    listResponse = () => json(200, []);
    render(view());
    expect(await screen.findByText('No playbooks yet')).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load playbooks")).not.toBeInTheDocument();
  });

  it('says it could not load them, with the reason and a working Retry, and does not claim there are none', async () => {
    listResponse = () => json(503, {});
    const { container } = render(view());
    expect(await screen.findByText("Couldn't load playbooks")).toBeInTheDocument();
    expect(screen.getByText(/Failed to fetch/)).toBeInTheDocument();
    expect(screen.queryByText('No playbooks yet')).not.toBeInTheDocument();
    expect(screen.queryByTestId('gallery')).not.toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo/i);
    expect(screen.queryByText(/showing what was last loaded/)).not.toBeInTheDocument(); // nothing was ever loaded

    listResponse = () => json(200, playbooks);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('Isolate compromised host')).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load playbooks")).not.toBeInTheDocument();
  });

  it('keeps the last loaded playbooks, and says the refresh failed, when a later refresh fails', async () => {
    render(view());
    await screen.findByText('Isolate compromised host');
    listResponse = () => json(500, {});
    await act(async () => { await mutate('/api/v1/playbooks'); });
    expect(await screen.findByText(/Couldn.t refresh playbooks; showing what was last loaded/)).toBeInTheDocument();
    expect(screen.getByText('Isolate compromised host')).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load playbooks")).not.toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText('No playbooks yet')).not.toBeInTheDocument());
  });
});
