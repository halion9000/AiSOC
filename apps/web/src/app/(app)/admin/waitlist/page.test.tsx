import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import AdminWaitlistPage from './page';

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const entry = {
  id: 'w1', email: 'cso@customer.com', company: 'Customer Co', role: 'CSO', soc_stack: ['splunk'], motivation: 'evaluating',
  status: 'new', provisioned_tenant_id: null, created_at: '2026-10-07T00:00:00Z', contacted_at: null, onboarded_at: null,
};
const provisioned = {
  tenant_id: 't1', tenant_slug: 'customer-co', tenant_name: 'Customer Co', waitlist_entry_id: 'w1',
  admin_user: { id: 'u1', email: 'cso@customer.com', role: 'admin' }, admin_invite: { token: 'tok', expires_at: '2026-10-15T00:00:00Z', url: 'https://example.com/invite/tok' },
  demo_seeded: false, aisoc_credential_key_fingerprint: 'abc123',
};

// Promoting a waitlist entry sent `seed_demo: true`, which loaded the demo dataset (a few thousand lines of invented incidents) into the customer's brand-new tenant: their first login showed fabricated alerts and cases.
describe('promoting a waitlist entry', () => {
  beforeEach(() => {
    authFetch.mockReset();
    authFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (url.startsWith('/api/v1/waitlist/entries') && (!init || init.method === 'GET')) return json(200, { entries: [entry], total: 1 });
      if (url === '/api/v1/admin/tenants/provision') return json(201, provisioned);
      return json(404, {});
    });
  });

  async function promote() {
    render(<AdminWaitlistPage />);
    const button = await screen.findByRole('button', { name: /Promote to tenant/ });
    await userEvent.setup().click(button);
    await waitFor(() => expect(authFetch.mock.calls.some(([u]) => u === '/api/v1/admin/tenants/provision')).toBe(true));
  }

  it('asks the server NOT to seed demo data into the customer\'s new workspace', async () => {
    await promote();
    const [, init] = authFetch.mock.calls.find(([u]) => u === '/api/v1/admin/tenants/provision')!;
    const body = JSON.parse(init.body);
    expect(body).toEqual({ waitlist_entry_id: 'w1', seed_demo: false });
  });

  it('does not advertise seeding a demo dataset, before or after provisioning', async () => {
    const { container } = render(<AdminWaitlistPage />);
    await screen.findByRole('button', { name: /Promote to tenant/ });
    expect(container.textContent).not.toMatch(/demo dataset|seed the|demo data/i);
    await userEvent.setup().click(screen.getByRole('button', { name: /Promote to tenant/ }));
    expect(await screen.findByText(/Tenant provisioned/)).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo dataset|seeded|demo data/i);
    expect(container.textContent).toContain('customer-co');
  });

  it('still shows the invite details once provisioned', async () => {
    await promote();
    expect(await screen.findByText('customer-co')).toBeInTheDocument();
    expect(screen.getByText('cso@customer.com', { selector: 'span' })).toBeInTheDocument();
    expect(screen.getByText('abc123')).toBeInTheDocument();
  });
});
