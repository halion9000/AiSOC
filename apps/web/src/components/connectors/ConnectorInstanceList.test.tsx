import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

vi.mock('next/link', () => ({ default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => <a href={href} {...rest}>{children}</a> }));
vi.mock('./ConnectorLogDrawer', () => ({ ConnectorLogDrawer: ({ connector, onClose }: { connector: { name: string }; onClose: () => void }) => <div data-testid="log-drawer">{connector.name}<button onClick={onClose}>close log</button></div> }));

import { ConnectorInstanceList, feedVendor, hasUnmappedClients } from './ConnectorInstanceList';
import type { Connector } from '@/lib/api';

const connector = (over: Partial<Connector> = {}): Connector => ({ id: 'c1', name: 'CrowdStrike prod', type: 'crowdstrike', status: 'active', alertCount: 1234, lastSync: new Date(Date.now() - 5 * 60_000).toISOString(), ...over });
const noop = () => {};

describe('helpers', () => {
  it('says a message is about unmapped clients only when it says "not mapped yet"', () => {
    expect(hasUnmappedClients('3 devices skipped: client not mapped yet')).toBe(true);
    expect(hasUnmappedClients('Everything fine')).toBe(false);
    expect(hasUnmappedClients(undefined)).toBe(false);
  });
  it('finds the tool a CORE-fed connector reads from, and nothing for any other connector', () => {
    expect(feedVendor(connector({ type: 'core_feed', config: { vendor: 'huntress' } }))).toBe('huntress');
    expect(feedVendor(connector({ type: 'core_feed', connectorConfig: { vendor: 'ninjaone' } }))).toBe('ninjaone');
    expect(feedVendor(connector({ type: 'core_feed', config: {} }))).toBeUndefined();
    expect(feedVendor(connector({ type: 'splunk', config: { vendor: 'x' } }))).toBeUndefined();
  });
});

describe('ConnectorInstanceList', () => {
  it('shows a loading skeleton while loading, and no cards', () => {
    const { container } = render(<ConnectorInstanceList connectors={[connector()]} isLoading onTest={noop} onAdd={noop} />);
    expect(screen.queryByText('CrowdStrike prod')).toBeNull();
    expect(container.firstElementChild?.children.length).toBe(3);
  });

  it('invites the first connector when there are none, and the button calls onAdd', async () => {
    const onAdd = vi.fn();
    render(<ConnectorInstanceList connectors={[]} onTest={noop} onAdd={onAdd} />);
    expect(screen.getByText('No connectors yet')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /add your first connector/i }));
    expect(onAdd).toHaveBeenCalledTimes(1);
  });

  it('shows each connector with its status, events and last sync, and a trailing add tile', async () => {
    const onAdd = vi.fn();
    render(<ConnectorInstanceList connectors={[connector(), connector({ id: 'c2', name: 'Okta', type: 'okta', status: 'inactive', alertCount: 0, lastSync: undefined })]} onTest={noop} onAdd={onAdd} />);
    expect(screen.getByText('CrowdStrike prod')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByText('1,234')).toBeInTheDocument();
    expect(screen.getByText('5m ago')).toBeInTheDocument();
    expect(screen.getByText('Inactive')).toBeInTheDocument();
    expect(screen.getByText('never')).toBeInTheDocument();
    await userEvent.click(screen.getByText('Add Connector'));
    expect(onAdd).toHaveBeenCalled();
  });

  it('a failed run is shown as an alert with the reason; a partly failed one says it needs attention', () => {
    render(<ConnectorInstanceList connectors={[connector({ status: 'error', errorMessage: 'Blumira refused the key (401)' }), connector({ id: 'c2', name: 'Huntress', status: 'warning', errorMessage: 'devices failed' })]} onTest={noop} onAdd={noop} />);
    const alerts = screen.getAllByRole('alert').map((a) => a.textContent);
    expect(alerts[0]).toBe('Last run failed: Blumira refused the key (401)');
    expect(alerts[1]).toBe('Needs attention: devices failed');
  });

  it('Test, Configure and Delete call back with the right connector, and the test result is shown', async () => {
    const onTest = vi.fn();
    const onConfigure = vi.fn();
    const onDelete = vi.fn();
    const c = connector();
    render(<ConnectorInstanceList connectors={[c]} onTest={onTest} onAdd={noop} onConfigure={onConfigure} onDelete={onDelete} testResults={{ c1: true }} />);
    await userEvent.click(screen.getByRole('button', { name: 'Test' }));
    await userEvent.click(screen.getByRole('button', { name: 'Configure' }));
    await userEvent.click(screen.getByRole('button', { name: 'Delete CrowdStrike prod' }));
    expect(onTest).toHaveBeenCalledWith('c1');
    expect(onConfigure).toHaveBeenCalledWith(c);
    expect(onDelete).toHaveBeenCalledWith(c);
    expect(screen.getByText('✓ Connection successful')).toBeInTheDocument();
  });

  it('a failed test says so, and a connector being tested cannot be tested again', () => {
    render(<ConnectorInstanceList connectors={[connector()]} onTest={noop} onAdd={noop} testingId="c1" testResults={{ c1: false }} />);
    expect(screen.getByRole('button', { name: 'Test' })).toBeDisabled();
    expect(screen.getByText('✗ Connection failed')).toBeInTheDocument();
  });

  it('Configure is unavailable when the parent gave no way to configure', () => {
    render(<ConnectorInstanceList connectors={[connector()]} onTest={noop} onAdd={noop} />);
    expect(screen.getByRole('button', { name: 'Configure' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: /^Delete/ })).toBeNull();
  });

  it('a feed set up in CORE says it is managed there, syncs instead of testing, and opens its log', async () => {
    const onTest = vi.fn();
    render(<ConnectorInstanceList connectors={[connector({ id: 'f1', name: 'Huntress (via CORE)', type: 'core_feed', config: { vendor: 'huntress' } })]} onTest={onTest} onAdd={noop} />);
    expect(screen.getByText('Managed in CORE')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Configure' })).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: 'Sync' }));
    expect(onTest).toHaveBeenCalledWith('f1');
    await userEvent.click(screen.getByRole('button', { name: 'Open the log for Huntress (via CORE)' }));
    expect(screen.getByTestId('log-drawer')).toHaveTextContent('Huntress (via CORE)');
    await userEvent.click(screen.getByText('close log'));
    expect(screen.queryByTestId('log-drawer')).toBeNull();
  });

  it('a tool that only supplies devices counts devices read, and offers Map clients when its devices wait for a client', () => {
    render(<ConnectorInstanceList connectors={[connector({ id: 'd1', name: 'DNSFilter (via CORE)', type: 'core_feed', config: { vendor: 'dnsfilter', kind: 'devices', devices: 40 }, status: 'warning', errorMessage: '12 devices not stored: client not mapped yet' })]} onTest={noop} onAdd={noop} />);
    expect(screen.getByText('Devices read')).toBeInTheDocument();
    expect(screen.getByText('40')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Map clients' })).toHaveAttribute('href', '/mssp?vendor=dnsfilter');
  });

  it('shows the freshness verdict, recent schema drift with how many fields, and dropped events', () => {
    render(
      <ConnectorInstanceList
        connectors={[connector({ freshness: { status: 'yellow', seconds_since_last_event: 1800, expected_cadence_seconds: 300 } as never, lastSchemaDriftAt: new Date().toISOString(), lastDriftDetails: { added: ['a', 'b'], removed: ['c'] }, eventsDropped: 1500 })]}
        onTest={noop}
        onAdd={noop}
      />,
    );
    expect(screen.getByText('Late').closest('span')).toHaveAttribute('title', 'Last event 30m ago, expected every 5m');
    const drift = screen.getByText(/Schema drift/);
    expect(within(drift).getByText('+2/-1')).toBeInTheDocument();
    expect(screen.getByText(/1,500 dropped/)).toBeInTheDocument();
  });
});
