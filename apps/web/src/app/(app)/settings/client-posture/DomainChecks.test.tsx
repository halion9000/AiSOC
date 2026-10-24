import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import { DomainChecks } from './DomainChecks';

const reply = (body: unknown, ok = true) => ({ ok, status: ok ? 200 : 500, json: () => Promise.resolve(body) });
const finding = (status: string, summary: string, record: string | null = null) => ({ status, summary, record });

beforeEach(() => authFetch.mockReset());

describe('DomainChecks', () => {
  it('shows each domain with its SPF, DMARC and DKIM verdicts and where its mail goes', async () => {
    authFetch.mockResolvedValue(
      reply({
        domains: [
          { domain: 'acme.com', status: 'needs_work', mx: ['acme-com.mail.protection.outlook.com'], mail_provider: 'Microsoft 365', spf: finding('good', 'SPF is published and rejects other senders.', 'v=spf1 -all'), dmarc: finding('needs_work', 'DMARC policy is none'), dkim: finding('missing', 'No DKIM key found') },
        ],
      }),
    );
    render(<DomainChecks clientId="c1" />);
    const box = await screen.findByTestId('domain-checks');
    expect(authFetch).toHaveBeenCalledWith('/api/v1/client-posture/c1/domains');
    expect(within(box).getByText('acme.com')).toBeInTheDocument();
    expect(within(box).getByText('Mail: Microsoft 365')).toBeInTheDocument();
    expect(within(within(box).getByTestId('check-SPF')).getByText('Good')).toBeInTheDocument();
    expect(within(within(box).getByTestId('check-DMARC')).getByText('Needs work')).toBeInTheDocument();
    expect(within(within(box).getByTestId('check-DKIM')).getByText('Missing')).toBeInTheDocument();
    expect(within(box).getByText('v=spf1 -all')).toBeInTheDocument();
  });

  it('says where the domains come from when there are none', async () => {
    authFetch.mockResolvedValue(reply({ domains: [] }));
    render(<DomainChecks clientId="c1" />);
    expect(await screen.findByTestId('no-domains')).toHaveTextContent('Identities');
  });

  it('shows the same message for an older API (404) or a reply without a domain list', async () => {
    authFetch.mockResolvedValue(reply({}, false));
    const { unmount } = render(<DomainChecks clientId="c1" />);
    expect(await screen.findByTestId('no-domains')).toBeInTheDocument();
    unmount();
    authFetch.mockResolvedValue(reply({ devices: {} }));
    render(<DomainChecks clientId="c1" />);
    expect(await screen.findByTestId('no-domains')).toBeInTheDocument();
  });
});
