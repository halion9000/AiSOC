import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
const swrMutate = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));
vi.mock('swr', () => ({ mutate: swrMutate }));

import { forkPlaybook, isShippedPack } from './packHelpers';
import { EnabledToggle } from './rowActions';
import type { Playbook } from './types';

/**
 * Playbooks are a shared, READ-ONLY library plus each tenant's own; a tenant customises a library playbook by forking (cloning) it.
 *
 * Before: "Fork" POSTed a copy through the generic create endpoint (no provenance), library items were told apart by a heuristic, and the enable toggle PUT the flag on ANY playbook, library included
 * (which flipped it for every tenant) and ignored a refusal, so a failure looked like the switch quietly flipping back.
 */
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

function playbook(over: Partial<Playbook> = {}): Playbook {
  return {
    id: 'phishing-triage', name: 'Phishing triage', description: 'd', version: '1.0.0', tags: [], trigger: { on: 'manual' }, steps: [], author: 'AiSOC', enabled: true, created_at: '', updated_at: '', ...over,
  } as Playbook;
}

beforeEach(() => {
  authFetch.mockReset();
  swrMutate.mockReset();
});

describe('forking a playbook', () => {
  it('asks the SERVER to clone it, naming the copy', async () => {
    const created = playbook({ id: 'c8d3-new', scope: 'tenant', cloned_from: 'phishing-triage', enabled: false });
    authFetch.mockResolvedValue(json(201, created));
    const out = await forkPlaybook(playbook());
    expect(authFetch).toHaveBeenCalledTimes(1);
    const [url, init] = authFetch.mock.calls[0];
    expect(url).toBe('/api/v1/playbooks/phishing-triage/clone');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body)).toEqual({ name: 'Phishing triage (fork)' });
    expect(out).toEqual(created);
  });

  it('does not build the copy in the browser any more (no id, tags or enabled flag are sent)', async () => {
    authFetch.mockResolvedValue(json(201, playbook()));
    await forkPlaybook(playbook({ tags: ['edr'], enabled: true }));
    expect(Object.keys(JSON.parse(authFetch.mock.calls[0][1].body))).toEqual(['name']);
  });

  it('encodes the id so it cannot change the path it is sent to', async () => {
    authFetch.mockResolvedValue(json(201, playbook()));
    await forkPlaybook(playbook({ id: '../../admin?x=1#y' }));
    expect(authFetch.mock.calls[0][0]).toBe('/api/v1/playbooks/..%2F..%2Fadmin%3Fx%3D1%23y/clone');
  });

  // EXACT messages: a regex also matches the raw JSON body ({"detail":"..."} contains the same words), so it could not tell a parsed explanation from an unparsed one.
  it.each([
    [404, { detail: 'Playbook not found' }, 'Fork failed: HTTP 404 \u2014 Playbook not found'],
    [409, { detail: 'This tenant already has 200 custom playbooks; delete some before adding more' }, 'Fork failed: HTTP 409 \u2014 This tenant already has 200 custom playbooks; delete some before adding more'],
    [503, { detail: 'Custom playbooks cannot be stored right now: DATABASE_URL is not configured' }, 'Fork failed: HTTP 503 \u2014 Custom playbooks cannot be stored right now: DATABASE_URL is not configured'],
    [403, { detail: 'Permission denied' }, 'Fork failed: HTTP 403 \u2014 Permission denied'],
  ])('says exactly why when the server refuses (%s), without showing raw JSON', async (status, body, expected) => {
    authFetch.mockResolvedValue(json(status, body));
    await expect(forkPlaybook(playbook())).rejects.toHaveProperty('message', expected);
  });

  it('keeps a structured (non-string) detail readable by falling back to the raw body rather than "[object Object]"', async () => {
    authFetch.mockResolvedValue(json(422, { detail: [{ loc: ['steps'], msg: 'bad' }] }));
    const err = await forkPlaybook(playbook()).catch((e: Error) => e);
    expect((err as Error).message).toMatch(/^Fork failed: HTTP 422 \u2014 \{"detail":\[\{"loc":\["steps"\],"msg":"bad"\}\]\}$/);
    expect((err as Error).message).not.toContain('[object Object]');
  });

  it('shows a non-JSON failure body as it is, and copes with an empty one', async () => {
    authFetch.mockResolvedValueOnce(new Response('upstream exploded', { status: 502 }));
    await expect(forkPlaybook(playbook())).rejects.toThrow('Fork failed: HTTP 502 \u2014 upstream exploded');
    authFetch.mockResolvedValueOnce(new Response('', { status: 500 }));
    await expect(forkPlaybook(playbook())).rejects.toThrow(/^Fork failed: HTTP 500$/);
  });
});

describe('which playbooks are the shared library', () => {
  it('trusts the server: scope=library is library whatever the id or author look like', () => {
    expect(isShippedPack(playbook({ scope: 'library', id: '3f1c2d9e-0000-4000-8000-000000000000', author: 'someone' }))).toBe(true);
  });

  it('trusts the server: scope=tenant is never library, even if it looks like a shipped pack', () => {
    expect(isShippedPack(playbook({ scope: 'tenant', id: 'supply-vendor-breach-v1', author: 'AiSOC' }))).toBe(false);
  });

  it('falls back to the heuristic when an older server omits scope', () => {
    expect(isShippedPack(playbook({ scope: undefined, id: 'supply-vendor-breach-v1' }))).toBe(true);
    expect(isShippedPack(playbook({ scope: undefined, id: '3f1c2d9e-0000-4000-8000-000000000000' }))).toBe(false);
  });
});

describe('the enable toggle', () => {
  it('is locked for a shared library playbook, says why, and never calls the server', async () => {
    render(<EnabledToggle playbook={playbook({ scope: 'library' })} />);
    const toggle = screen.getByRole('button', { name: /Disable Phishing triage/ });
    expect(toggle).toBeDisabled();
    expect(toggle).toHaveAttribute('aria-disabled', 'true');
    expect(toggle).toHaveAttribute('title', expect.stringMatching(/read-only.*Fork it/i));
    await userEvent.click(toggle);
    expect(authFetch).not.toHaveBeenCalled();
  });

  it("flips the flag on a tenant's own playbook and refreshes the list", async () => {
    authFetch.mockResolvedValue(json(200, {}));
    render(<EnabledToggle playbook={playbook({ scope: 'tenant', id: 'c8d3-new', enabled: false })} />);
    await userEvent.click(screen.getByRole('button', { name: /Enable Phishing triage/ }));
    await waitFor(() => expect(swrMutate).toHaveBeenCalledWith('/api/v1/playbooks'));
    const [url, init] = authFetch.mock.calls[0];
    expect(url).toBe('/api/v1/playbooks/c8d3-new');
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body)).toEqual({ enabled: true });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows the server\'s reason when the change is refused, and does not pretend it worked', async () => {
    authFetch.mockResolvedValue(json(403, { detail: 'Shared library playbooks are read-only. Clone it into your tenant to customise it.' }));
    render(<EnabledToggle playbook={playbook({ scope: 'tenant', id: 'c8d3-new' })} />);
    await userEvent.click(screen.getByRole('button', { name: /Disable Phishing triage/ }));
    expect(await screen.findByRole('alert')).toHaveTextContent('read-only');
    expect(swrMutate).not.toHaveBeenCalled();
  });

  it('shows a network failure, then clears it on the next attempt', async () => {
    authFetch.mockRejectedValueOnce(new Error('Failed to fetch'));
    render(<EnabledToggle playbook={playbook({ scope: 'tenant', id: 'c8d3-new' })} />);
    await userEvent.click(screen.getByRole('button', { name: /Disable Phishing triage/ }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to fetch');
    authFetch.mockResolvedValueOnce(json(200, {}));
    await userEvent.click(screen.getByRole('button', { name: /Disable Phishing triage/ }));
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
  });

  it('falls back to a generic message when a refusal has no body', async () => {
    authFetch.mockResolvedValue(new Response('', { status: 500 }));
    render(<EnabledToggle playbook={playbook({ scope: 'tenant', id: 'c8d3-new' })} />);
    await userEvent.click(screen.getByRole('button', { name: /Disable Phishing triage/ }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not change this playbook (HTTP 500).');
  });

  it('encodes the id in the request path', async () => {
    authFetch.mockResolvedValue(json(200, {}));
    render(<EnabledToggle playbook={playbook({ scope: 'tenant', id: 'a/b?c' })} />);
    await userEvent.click(screen.getByRole('button', { name: /Disable Phishing triage/ }));
    expect(authFetch.mock.calls[0][0]).toBe('/api/v1/playbooks/a%2Fb%3Fc');
  });
});
