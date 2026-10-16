import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { Connector } from '@/lib/api';
import { ConnectorInstanceList } from './ConnectorInstanceList';

const base = { status: 'active', alertCount: 0, tenantId: 't1', category: 'edr' } as unknown as Connector;
const feed = { ...base, id: 'f1', name: 'Huntress (via CORE)', type: 'core_feed' } as Connector;
const okta = { ...base, id: 'o1', name: 'Okta production', type: 'okta' } as Connector;

function renderList(connectors: Connector[]) {
  return render(<ConnectorInstanceList connectors={connectors} onTest={vi.fn()} onAdd={vi.fn()} />);
}

describe('connectors that are set up in CORE', () => {
  it('say so, instead of showing a Configure button that does nothing', () => {
    renderList([feed]);
    expect(screen.getByText('Managed in CORE')).toBeInTheDocument();
    expect(screen.queryByText('Configure')).not.toBeInTheDocument();
  });

  it('leave every other connector with its Configure button', () => {
    renderList([okta]);
    expect(screen.getByText('Configure')).toBeInTheDocument();
    expect(screen.queryByText('Managed in CORE')).not.toBeInTheDocument();
  });
});

describe('why a CORE-fed connector failed', () => {
  it('shows the reason CORE reported on the card', () => {
    renderList([{ ...feed, errorMessage: 'Huntress returned 401' } as Connector]);
    expect(screen.getByRole('alert')).toHaveTextContent('Last run failed: Huntress returned 401');
  });

  it('a warning (alerts fine, a side job failed) is amber and says needs attention, not failed', () => {
    renderList([{ ...feed, status: 'warning', errorMessage: 'Alerts are flowing, but addigy devices: 500' } as Connector]);
    expect(screen.getByRole('alert')).toHaveTextContent('Needs attention: Alerts are flowing, but addigy devices: 500');
    expect(screen.getByRole('alert')).not.toHaveTextContent('failed');
    expect(screen.getByText('Warning')).toBeInTheDocument();
  });

  it('shows nothing when there is no reason', () => {
    renderList([feed]);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});

describe('the Configure button', () => {
  it('opens the editor for that connector instead of being disabled as "planned"', async () => {
    const onConfigure = vi.fn();
    const { container } = render(<ConnectorInstanceList connectors={[okta]} onTest={vi.fn()} onAdd={vi.fn()} onConfigure={onConfigure} />);
    const button = screen.getByRole('button', { name: 'Configure' });
    expect(button).toBeEnabled();
    expect(container.textContent).not.toMatch(/v1\.1/);
    await userEvent.setup().click(button);
    expect(onConfigure).toHaveBeenCalledWith(okta);
  });
});
