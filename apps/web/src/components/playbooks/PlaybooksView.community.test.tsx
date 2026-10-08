import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));
vi.mock('./PlaybooksGallery', () => ({ PlaybooksGallery: () => null }));
vi.mock('@/components/saved-views/SavedViewsBar', () => ({ SavedViewsBar: () => null }));
vi.mock('./DraftFromPromptDialog', () => ({ DraftFromPromptDialog: () => null }));

import { PlaybooksView } from './PlaybooksView';

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const playbook = { id: 'p1', name: 'Isolate compromised host', description: 'Isolate and notify', author: 'Someone', tags: [], status: 'approved', install_count: 2, rating: 0, rating_count: 0, submitted_at: '2026-10-08T00:00:00Z' };

let installResponse: () => Promise<Response>;

beforeEach(() => {
  authFetch.mockReset();
  installResponse = async () => json(200, { message: 'installed', playbook_id: 'pb-9' });
  authFetch.mockImplementation(async (url: string) => {
    if (url.includes('/install')) return installResponse();
    if (url.startsWith('/api/v1/community/playbooks')) return json(200, { items: [playbook], total: 1 });
    return json(200, []);
  });
});

async function openCommunityAndFindInstall() {
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <PlaybooksView />
    </SWRConfig>,
  );
  await userEvent.setup().click(screen.getAllByRole('button', { name: 'Community' })[0]);
  await screen.findByText('Isolate compromised host');
  return screen.getByRole('button', { name: 'Install' });
}

// Same defect as the detection catalog: the card said "Installed" whenever the request merely completed.
describe('installing a community playbook', () => {
  it('shows Installed when the server confirms', async () => {
    await userEvent.setup().click(await openCommunityAndFindInstall());
    await waitFor(() => expect(screen.getByRole('button', { name: 'Installed' })).toBeDisabled());
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(authFetch).toHaveBeenCalledWith('/api/v1/community/playbooks/p1/install', { method: 'POST' });
  });

  it('shows the server\'s reason, and NOT Installed, when the engine refuses it', async () => {
    installResponse = async () => json(422, { detail: 'Upstream service error' });
    await userEvent.setup().click(await openCommunityAndFindInstall());
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not install: Upstream service error');
    expect(screen.queryByRole('button', { name: 'Installed' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Install' })).toBeEnabled();
  });

  it('says so when the agents service is unavailable', async () => {
    installResponse = async () => json(503, { detail: 'Agents service unavailable' });
    await userEvent.setup().click(await openCommunityAndFindInstall());
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not install: Agents service unavailable');
    expect(screen.queryByRole('button', { name: 'Installed' })).not.toBeInTheDocument();
  });

  it('says so when the network fails', async () => {
    installResponse = async () => { throw new Error('network down'); };
    await userEvent.setup().click(await openCommunityAndFindInstall());
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not install: network down');
    expect(screen.queryByRole('button', { name: 'Installed' })).not.toBeInTheDocument();
  });
});
