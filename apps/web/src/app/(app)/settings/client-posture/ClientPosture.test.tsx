import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));
vi.mock('next/link', () => ({ default: ({ children, href, ...rest }: { children: React.ReactNode; href: string }) => <a href={href} {...rest}>{children}</a> }));

import { ClientPosture, coverage, postureLinks } from './ClientPosture';

const reply = (body: unknown, ok = true) => ({ ok, status: ok ? 200 : 500, json: () => Promise.resolve(body) });
const posture = (over: Record<string, unknown> = {}) => ({
  client_id: 'c1',
  client_name: 'Acme Dental',
  generated_at: '2026-10-19T10:00:00Z',
  devices: { devices: 40, needs_attention: 3, stale_agents: 1, not_in_huntress: 2, offline: 4 },
  identity: { people: 20, with_mfa: 15, not_required: 2, without_mfa: 3, admins_without_mfa: 1, refreshed_at: null },
  alerts: { open: 7, critical: 1, high: 2, without_ticket: 4 },
  open_cases: 2,
  ...over,
});

function serve(p: unknown) {
  authFetch.mockImplementation((url?: string) =>
    Promise.resolve((url ?? '').includes('/mssp/children') ? reply([{ id: 'c1', name: 'Acme Dental' }, { id: 'c0', name: 'Aardvark Vet' }]) : reply(p)),
  );
}

beforeEach(() => authFetch.mockReset());

describe('coverage', () => {
  it('is the share of people covered, or a dash when there are none', () => {
    expect(coverage({ people: 20, with_mfa: 15 })).toBe('75%');
    expect(coverage({ people: 0, with_mfa: 0 })).toBe('—');
  });
});

describe('ClientPosture', () => {
  it('lists the clients alphabetically and shows the posture of the one picked', async () => {
    serve(posture());
    render(<ClientPosture />);
    const select = await screen.findByLabelText('Client');
    await screen.findByRole('option', { name: 'Aardvark Vet' });
    const options = screen.getAllByRole('option').map((o) => o.textContent);
    expect(options).toEqual(['Pick a client', 'Aardvark Vet', 'Acme Dental']);
    await userEvent.selectOptions(select, 'c1');
    const page = await screen.findByTestId('posture');
    expect(page).toHaveTextContent('Acme Dental');
    expect(page).toHaveTextContent('40');
    expect(page).toHaveTextContent('75%');
    expect(page).toHaveTextContent('Open, no ticket');
    expect(authFetch).toHaveBeenCalledWith('/api/v1/client-posture/c1');
    expect(page.textContent?.toLowerCase()).not.toContain('second factor');
  });

  it('every number is a link to the list behind it, for this client', async () => {
    serve(posture());
    render(<ClientPosture />);
    await userEvent.selectOptions(await screen.findByLabelText('Client'), 'c1');
    const page = await screen.findByTestId('posture');
    const hrefOf = (name: RegExp) => within(page).getByRole('link', { name }).getAttribute('href');
    expect(hrefOf(/^Need attention: 3/)).toBe('/devices?client=c1&attention=1');
    expect(hrefOf(/^No Multi-Factor: 3/)).toBe('/settings/mfa?client=c1&which=without');
    expect(hrefOf(/^Open, no ticket: 4/)).toBe('/alerts?client=c1&ticket=none');
    expect(hrefOf(/^Open cases: 2/)).toBe('/cases?scope=all&client=c1');
    expect(within(page).getAllByRole("link")).toHaveLength(15);
  });

  it('says so when a client has no second-factor data', async () => {
    serve(posture({ identity: null }));
    render(<ClientPosture />);
    await userEvent.selectOptions(await screen.findByLabelText('Client'), 'c1');
    expect(await screen.findByTestId('no-identity')).toHaveTextContent('No Multi-Factor data yet');
  });

  it('shows an error plainly', async () => {
    authFetch.mockResolvedValue(reply({}, false));
    render(<ClientPosture />);
    expect(await screen.findByRole('alert')).toHaveTextContent('The API answered 500');
  });
});

describe('postureLinks', () => {
  it('names the client in every link and puts a client id in the address safely', () => {
    const links = postureLinks('a b&c');
    for (const href of Object.values(links)) expect(href).toContain('client=a%20b%26c');
    expect(links.stale).toBe('/devices?client=a%20b%26c&stale=1');
    expect(links.adminsWithout).toBe('/settings/mfa?client=a%20b%26c&which=without&admins=1');
  });
});

describe('the tools a client is linked to', () => {
  const tools = [
    { vendor: 'ninjaone', vendor_client_id: '83', vendor_client_name: 'Acme Dental' },
    { vendor: 'petra', vendor_client_id: '5', vendor_client_name: 'Acme' },
    { vendor: 'screenconnect', vendor_client_id: 'Acme Dental', vendor_client_name: 'Acme Dental' },
  ];

  async function show(body: unknown) {
    serve(body);
    render(<ClientPosture />);
    await userEvent.selectOptions(await screen.findByLabelText('Client'), 'c1');
    return screen.findByTestId('posture');
  }

  it('shows each tool as its logo, linking to the client page in tools whose address is known', async () => {
    await show(posture({ tools }));
    const section = screen.getByLabelText('Tools this client is linked to');
    const ninja = within(section).getByRole('link', { name: /NinjaOne/ });
    expect(ninja).toHaveAttribute('href', 'https://app.ninjarmm.com/#/customerDashboard/83/overview');
    expect(ninja).toHaveAttribute('target', '_blank');
    expect(ninja).toHaveAttribute('rel', expect.stringContaining('noopener'));
    expect(within(section).getByRole('link', { name: /ScreenConnect/ })).toHaveAttribute('href', expect.stringContaining('Acme%20Dental'));
  });

  it('shows a tool with no known page as a logo without a link, and says so on hover', async () => {
    await show(posture({ tools }));
    const section = screen.getByLabelText('Tools this client is linked to');
    expect(within(section).queryByRole('link', { name: /Petra/ })).not.toBeInTheDocument();
    expect(within(section).getByTitle(/Petra: Acme \(no link to this tool's page yet\)/)).toBeInTheDocument();
  });

  it('shows nothing when the client is linked to no tool, or the API does not send tools', async () => {
    await show(posture({ tools: [] }));
    expect(screen.queryByLabelText('Tools this client is linked to')).not.toBeInTheDocument();
  });

  it('opens a Google Datto SaaS customer on the list and a Microsoft one on its own page', async () => {
    await show(
      posture({
        tools: [
          { vendor: 'datto-saas', vendor_client_id: '433930', vendor_client_name: 'G Co', product: 'google' },
          { vendor: 'datto-saas', vendor_client_id: '494057', vendor_client_name: 'M Co', product: 'microsoft' },
        ],
      }),
    );
    const links = within(screen.getByLabelText('Tools this client is linked to')).getAllByRole('link');
    expect(links.map((l) => l.getAttribute('href'))).toEqual(['https://portal.dattobackup.com/status/saas/overview', 'https://app.backupify.com/office365/customers/494057']);
  });
});
