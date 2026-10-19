import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import type { Alert } from '@/lib/api';

const vendorActions = vi.hoisted(() => vi.fn());
const related = vi.hoisted(() => vi.fn());
const addTicket = vi.hoisted(() => vi.fn());
const removeTicket = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ alertsApi: { vendorActions, addTicket, removeTicket, related } }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock('react-hot-toast', () => ({ default: toast }));

import { AlertContext, alertContextOf, sourceLink, toolLinks } from './AlertContext';

const alert = (over: Partial<Alert> = {}): Alert =>
  ({ id: 'a1', title: 't', description: 'd', severity: 'high', status: 'new', source: 'huntress', tenantId: 't1', riskScore: 5, createdAt: '2026-10-18T00:00:00Z', ...over }) as Alert;

const renderCtx = (a: Alert) =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <AlertContext alert={a} />
    </SWRConfig>,
  );

beforeEach(() => {
  vendorActions.mockReset().mockResolvedValue({ supported: false, actions: [], tickets: [] });
  related.mockReset().mockResolvedValue({ items: [], more: 0 });
  addTicket.mockReset().mockResolvedValue({ tickets: [] });
  removeTicket.mockReset().mockResolvedValue({ tickets: [] });
  toast.success.mockReset();
  toast.error.mockReset();
});

describe('alertContextOf', () => {
  it('uses every host the alert names, falling back to the first one, and never invents anything', () => {
    expect(alertContextOf(alert({ affectedHosts: ['PC-1', 'PC-2'], affectedUsers: ['a@b.com'], affectedIps: ['10.0.0.1'], clientName: 'Acme' }))).toEqual({ company: 'Acme', hosts: ['PC-1', 'PC-2'], users: ['a@b.com'], ips: ['10.0.0.1'] });
    expect(alertContextOf(alert({ device: 'PC-9' })).hosts).toEqual(['PC-9']);
    expect(alertContextOf(alert())).toEqual({ company: null, hosts: [], users: [], ips: [] });
  });
});

describe('AlertContext', () => {
  it('shows the company, links each device to the Devices page, and lists the user and address', async () => {
    renderCtx(alert({ clientName: 'Acme Corp', affectedHosts: ['PC-1'], affectedUsers: ['kevin@acme.com'], affectedIps: ['203.0.113.9'] }));
    expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'PC-1' })).toHaveAttribute('href', '/devices?search=PC-1');
    expect(screen.getByText('kevin@acme.com')).toBeInTheDocument();
    expect(screen.getByText('203.0.113.9')).toBeInTheDocument();
  });

  it('says plainly when the alert names no device or user, rather than leaving a blank', async () => {
    renderCtx(alert());
    expect(screen.getByText('This alert names no device')).toBeInTheDocument();
    expect(screen.getByText('This alert names no user')).toBeInTheDocument();
    expect(screen.getByText('Your own organization')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText('No HaloPSA ticket matched')).toBeInTheDocument());
  });

  it('shows the HaloPSA ticket that matched, with a link only when it is a plain https address', async () => {
    vendorActions.mockResolvedValue({ supported: false, actions: [], tickets: [
      { system: 'halopsa', id: '4521', summary: 'Huntress: ransomware canary', status: 'Open', url: 'https://halo.example.com/ticket?id=4521' },
      { system: 'halopsa', id: '4522', summary: 'Other', url: 'javascript:alert(1)' },
    ] });
    renderCtx(alert());
    expect(await screen.findByText('#4521')).toBeInTheDocument();
    expect(screen.getByText(/Huntress: ransomware canary/)).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'Open in HaloPSA' })).toHaveLength(1);
    expect(screen.getByRole('link', { name: 'Open in HaloPSA' })).toHaveAttribute('href', 'https://halo.example.com/ticket?id=4521');
  });
});

describe('entering a ticket by hand', () => {
  it('links the ticket with only a number, sending the optional fields only when filled', async () => {
    renderCtx(alert());
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a ticket' }));
    expect(screen.getByRole('button', { name: 'Link ticket' })).toBeDisabled();
    await user.type(screen.getByLabelText('Ticket number'), '#4521');
    await user.click(screen.getByRole('button', { name: 'Link ticket' }));
    await waitFor(() => expect(addTicket).toHaveBeenCalledWith('a1', { id: '#4521' }));
    expect(toast.success).toHaveBeenCalledWith('Ticket 4521 linked.');
    expect(screen.queryByTestId('add-ticket')).not.toBeInTheDocument();
  });

  it('sends the summary and link when they are given, and shows the API\'s reason when it refuses', async () => {
    addTicket.mockRejectedValue(new Error('A ticket number is letters, digits, dashes and underscores (up to 40), for example 4521.'));
    renderCtx(alert());
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a ticket' }));
    await user.type(screen.getByLabelText('Ticket number'), '4521');
    await user.type(screen.getByLabelText('Ticket summary'), 'Canary');
    await user.type(screen.getByLabelText('Ticket link'), 'https://halo.example.com/t/4521');
    await user.click(screen.getByRole('button', { name: 'Link ticket' }));
    await waitFor(() => expect(addTicket).toHaveBeenCalledWith('a1', { id: '4521', summary: 'Canary', url: 'https://halo.example.com/t/4521' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith(expect.stringContaining('A ticket number is letters')));
  });

  it('marks a ticket added by hand and offers to remove only that one', async () => {
    vendorActions.mockResolvedValue({ supported: false, actions: [], tickets: [
      { system: 'halopsa', id: '100', summary: 'From CORE' },
      { system: 'halopsa', id: '200', summary: 'Typed', manual: true },
    ] });
    renderCtx(alert());
    expect(await screen.findByText('added by hand')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Remove ticket/ })).toHaveLength(1);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Remove ticket 200' }));
    await waitFor(() => expect(removeTicket).toHaveBeenCalledWith('a1', '200'));
  });
});

describe('links out to the tools', () => {
  it('makes the ticket number itself a link to Halo when the ticket has one', async () => {
    vendorActions.mockResolvedValue({ supported: false, actions: [], tickets: [{ system: 'halopsa', id: '4521', summary: 'Canary', url: 'https://acme.halopsa.com/tickets?id=4521' }] });
    renderCtx(alert());
    const link = await screen.findByRole('link', { name: '#4521' });
    expect(link).toHaveAttribute('href', 'https://acme.halopsa.com/tickets?id=4521');
    expect(link).toHaveAttribute('target', '_blank');
  });

  it('leaves a ticket that has no link as plain text', async () => {
    vendorActions.mockResolvedValue({ supported: false, actions: [], tickets: [{ system: 'halopsa', id: '9', summary: 'No link' }] });
    renderCtx(alert());
    expect(await screen.findByText('#9')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: '#9' })).not.toBeInTheDocument();
  });

  it('opens the alert in the tool that raised it, named after the tool, and only for a plain https link', async () => {
    expect(sourceLink(alert({ source: 'petra', sourceUrl: 'https://app.petrasecurity.com/tenant/x/incidents/1' }))).toEqual({ href: 'https://app.petrasecurity.com/tenant/x/incidents/1', label: 'Open in Petra' });
    expect(sourceLink(alert({ source: 'petra', sourceUrl: 'javascript:alert(1)' }))).toBeNull();
    expect(sourceLink(alert({ source: 'huntress' }))).toBeNull();
    renderCtx(alert({ source: 'blumira', sourceUrl: 'https://app.blumira.com/x/query/findings/1' }));
    expect(screen.getByRole('link', { name: 'Open in Blumira' })).toHaveAttribute('href', 'https://app.blumira.com/x/query/findings/1');
  });
});

describe('links to the device and the user in the tool', () => {
  const links = { device_url: 'https://goliveoak.huntress.io/org/132469/agents/18699500', user_url: 'https://goliveoak.huntress.io/org/530195/managed_identity/identities/22018043973' };

  it('shows an Open in <tool> link beside the device and beside the user', () => {
    renderCtx(alert({ source: 'huntress', affectedHosts: ['PC-1'], affectedUsers: ['kevin@acme.com'], links }));
    const open = screen.getAllByRole('link', { name: 'Open in Huntress' });
    expect(open.map((a) => a.getAttribute('href'))).toEqual([links.device_url, links.user_url]);
  });

  it('shows nothing extra when the tool gave no link, and refuses a link that is not plain https', () => {
    expect(toolLinks(alert({ source: 'huntress' }))).toEqual({ device: null, user: null });
    expect(toolLinks(alert({ source: 'huntress', links: { device_url: 'javascript:alert(1)', user_url: 'http://insecure.example.com' } }))).toEqual({ device: null, user: null });
    renderCtx(alert({ source: 'huntress', affectedHosts: ['PC-1'] }));
    expect(screen.queryByRole('link', { name: 'Open in Huntress' })).not.toBeInTheDocument();
  });
});

describe('other alerts about the same device or user', () => {
  it('lists them with the tool, why they match and a link, and counts the ones not shown', async () => {
    related.mockResolvedValue({
      items: Array.from({ length: 7 }, (_, i) => ({ id: `r${i}`, title: `Earlier ${i}`, severity: 'high', status: 'new', source: i === 0 ? 'petra' : 'huntress', created_at: '2026-10-1' + (i % 9) + 'T00:00:00Z', matched: i === 0 ? 'user' : 'device' })),
      more: 1,
    });
    renderCtx(alert({ affectedHosts: ['PC-1'] }));
    const section = await screen.findByTestId('related-alerts');
    expect(section).toHaveTextContent('Petra');
    expect(section).toHaveTextContent('same user');
    expect(screen.getByRole('link', { name: 'Earlier 0' })).toHaveAttribute('href', '/alerts/r0');
    expect(screen.getAllByRole('link', { name: /^Earlier/ })).toHaveLength(5);
    expect(section).toHaveTextContent('and 3 more');
  });

  it('shows nothing at all when there are no related alerts', async () => {
    renderCtx(alert({ affectedHosts: ['PC-1'] }));
    await waitFor(() => expect(related).toHaveBeenCalled());
    expect(screen.queryByTestId('related-alerts')).not.toBeInTheDocument();
  });
});
