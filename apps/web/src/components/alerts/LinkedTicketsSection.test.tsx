import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { LinkedTicket } from '@/lib/api';
import { LinkedTicketsList, safeTicketUrl } from './LinkedTicketsSection';

const found: LinkedTicket = { id: '123', system: 'halopsa', summary: 'Malware on ACME-FS01', status: 'Open', client: 'Acme Dental', url: 'https://acme.halopsa.com/tickets?id=123' };

describe('linked tickets', () => {
  it('shows the ticket, what it is about, its status and a link into HaloPSA', () => {
    render(<LinkedTicketsList tickets={[found]} />);
    expect(screen.getByText('#123')).toBeInTheDocument();
    expect(screen.getByText('Malware on ACME-FS01')).toBeInTheDocument();
    expect(screen.getByText('Open')).toBeInTheDocument();
    expect(screen.getByText('Acme Dental')).toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'Open in HaloPSA' });
    expect(link).toHaveAttribute('href', 'https://acme.halopsa.com/tickets?id=123');
    expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'));
  });

  it('says so when HaloPSA does not know the ticket, rather than inventing a summary', () => {
    render(<LinkedTicketsList tickets={[{ id: '999', system: 'halopsa' }]} />);
    expect(screen.getByText('Not found in HaloPSA')).toBeInTheDocument();
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('renders nothing when there are no tickets', () => {
    const { container } = render(<LinkedTicketsList tickets={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('only ever links to a plain https address', () => {
    expect(safeTicketUrl('https://a.halopsa.com/tickets?id=1')).toBe('https://a.halopsa.com/tickets?id=1');
    for (const bad of ['javascript:alert(1)', 'http://a.com', 'data:text/html,x', '', undefined, 'https://a b']) expect(safeTicketUrl(bad)).toBeNull();
    render(<LinkedTicketsList tickets={[{ ...found, url: 'javascript:alert(1)' }]} />);
    expect(screen.queryByRole('link')).toBeNull();
  });
});
