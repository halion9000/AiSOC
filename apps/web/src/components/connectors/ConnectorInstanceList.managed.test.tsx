import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
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
