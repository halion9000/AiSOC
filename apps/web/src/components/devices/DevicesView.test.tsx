import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { DeviceList, DeviceRow } from '@/lib/api';

const listMock = vi.fn();
const masterMock = vi.fn();
const hideMock = vi.fn();
const unhideMock = vi.fn();
const childrenMock = vi.fn();
vi.mock('@/lib/api', () => ({
  devicesApi: { rollup: async () => [], merges: async () => [], list: (...a: unknown[]) => listMock(...a), setMaster: (...a: unknown[]) => masterMock(...a), hide: (...a: unknown[]) => hideMock(...a), unhide: (...a: unknown[]) => unhideMock(...a), duplicates: async () => ({ items: [] }) },
  msspApi: { listChildren: () => childrenMock() },
  apiErrorDetail: () => null,
}));
const routerParams = vi.hoisted(() => ({ current: new URLSearchParams('') }));
vi.mock('next/navigation', () => ({ useSearchParams: () => routerParams.current }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import DevicesView, { filtersFromParams, attentionOf, devicesLoadError, facts, protectionLines, ransomwareLinked, specs } from './DevicesView';

const NOW = '2026-10-15T15:00:00Z';
function device(over: Partial<DeviceRow> & { hostname: string }): DeviceRow {
  return {
    id: `d-${over.hostname}`, tenant_id: 't1', client_name: 'Acme', serial_number: null, os: 'Windows 11', os_version: null, manufacturer: null, model: null,
    ip_addresses: [], last_seen: NOW, first_seen: NOW, sources: [{ vendor: 'ninjaone', name: over.hostname, last_seen: NOW }], in_master: true, ...over,
  };
}
function list(items: DeviceRow[], over: Partial<DeviceList> = {}): DeviceList {
  return { master_vendor: null, summary: { total: items.length, not_in_master: 0 }, items, total: items.length, page: 1, page_size: 50, pages: 1, ...over };
}

beforeEach(() => {
  window.localStorage.clear();
  listMock.mockReset();
  masterMock.mockReset().mockResolvedValue({ master_vendor: 'ninjaone' });
  hideMock.mockReset().mockResolvedValue({ device_id: 'x', hidden_since: NOW });
  unhideMock.mockReset().mockResolvedValue({ device_id: 'x', hidden_since: null });
  childrenMock.mockReset().mockResolvedValue([{ id: 'c1', name: 'Acme', mssp_role: 'child' }]);
});

describe('a link into the tool that feeds a device', () => {
  it('opens the machine in ScreenConnect or NinjaOne, only for a plain https address', async () => {
    listMock.mockResolvedValue(
      list([
        device({
          hostname: 'LINKED-1',
          sources: [
            { vendor: 'screenconnect', name: 'LINKED-1', last_seen: NOW, details: { url: 'https://liveoakit.screenconnect.com/Host#Access/All%20Machines//abc/Join' } },
            { vendor: 'ninjaone', name: 'LINKED-1', last_seen: NOW, details: { url: 'javascript:alert(1)' } },
          ],
        }),
      ]),
    );
    render(<DevicesView />);
    await userEvent.click(await screen.findByText('LINKED-1'));
    const links = await screen.findAllByTestId('source-link');
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveTextContent('Open in ScreenConnect');
    expect(links[0]).toHaveAttribute('href', 'https://liveoakit.screenconnect.com/Host#Access/All%20Machines//abc/Join');
  });
});

describe('the not-in tiles for ScreenConnect and Field Effect', () => {
  it('appear only once that tool reports devices, and filter the list when pressed', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'A-1' })], { summary: { total: 1, not_in_master: 0, not_in_screenconnect: 4, not_in_fieldeffect: 2, reporting_tools: ['ninjaone', 'screenconnect', 'fieldeffect'] } }));
    render(<DevicesView />);
    expect(await screen.findByTestId('devices-missing-screenconnect')).toHaveTextContent('4');
    expect(screen.getByTestId('devices-missing-fieldeffect')).toHaveTextContent('2');
    expect(screen.getByText(/not iOS\/iPadOS\/tvOS/)).toBeInTheDocument();
    await userEvent.click(screen.getByTestId('devices-missing-screenconnect').closest('button') as HTMLElement);
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ missing: 'screenconnect' })));
  });

  it('are not shown while no device comes from those tools', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'A-2' })], { summary: { total: 1, not_in_master: 0, not_in_screenconnect: 99, reporting_tools: ['ninjaone'] } }));
    render(<DevicesView />);
    await screen.findByText('A-2');
    expect(screen.queryByTestId('devices-missing-screenconnect')).not.toBeInTheDocument();
    expect(screen.queryByTestId('devices-missing-fieldeffect')).not.toBeInTheDocument();
  });
});

describe('a tool that has not seen the device for 10 days', () => {
  const OLD = '2026-10-01T00:00:00Z';
  it('has a red line through its badge, with how long in the tooltip, while the other tools look normal', async () => {
    listMock.mockResolvedValue(
      list([
        device({
          hostname: 'LAPTOP-9',
          sources: [
            { vendor: 'huntress', name: 'LAPTOP-9', last_seen: NOW, last_checkin: OLD, stale: true },
            { vendor: 'ninjaone', name: 'LAPTOP-9', last_seen: NOW, last_checkin: NOW, stale: false },
          ],
        }),
      ]),
    );
    render(<DevicesView />);
    const row = (await screen.findByText('LAPTOP-9')).closest('tr') as HTMLElement;
    const struck = within(row).getAllByTestId('struck-badge');
    expect(struck).toHaveLength(1);
    expect(struck[0]).toHaveAttribute('data-vendor', 'huntress');
    expect(struck[0].getAttribute('title')).toMatch(/Huntress has not seen this device for \d+ days/);
  });

  it('a device that hid itself says so and offers no Show again button', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'DRAWER-PC', hidden_since: OLD, auto_hidden: true, sources: [{ vendor: 'ninjaone', name: 'DRAWER-PC', last_seen: NOW, last_checkin: OLD, stale: true }] })]));
    render(<DevicesView />);
    const row = (await screen.findByText('DRAWER-PC')).closest('tr') as HTMLElement;
    expect(within(row).getByTestId('auto-hidden')).toHaveTextContent('no tool has seen it for 10+ days');
    expect(within(row).queryByRole('button', { name: 'Show again' })).not.toBeInTheDocument();
  });
});

describe('DevicesView', () => {
  it('shows one row per device with every tool that feeds it', async () => {
    listMock.mockResolvedValue(
      list([
        device({
          hostname: 'FRONT-DESK',
          serial_number: 'SER-1',
          sources: [
            { vendor: 'ninjaone', name: 'FRONT-DESK', last_seen: NOW },
            { vendor: 'addigy', name: 'front-desk', last_seen: NOW },
          ],
        }),
      ]),
    );
    render(<DevicesView />);
    const row = (await screen.findByText('FRONT-DESK')).closest('tr') as HTMLElement;
    expect(within(row).getByText('SER-1')).toBeInTheDocument();
    expect(within(row).getByAltText('NinjaOne')).toBeInTheDocument();
    expect(within(row).getByAltText('Addigy')).toBeInTheDocument();
    expect(screen.getByTestId('devices-total')).toHaveTextContent('1');
  });

  it('marks a device ThreatMate only found by scanning the network, and no other', async () => {
    listMock.mockResolvedValue(
      list([
        device({ hostname: 'NUC-ASP-PRKNG', sources: [{ vendor: 'threatmate', name: 'NUC-ASP-PRKNG', last_seen: NOW, details: { discovery_source: 'network', discovered_on_network: true } }] }),
        device({ hostname: 'MANAGED-PC', sources: [{ vendor: 'threatmate', name: 'MANAGED-PC', last_seen: NOW, details: { discovery_source: 'agent', discovered_on_network: false } }] }),
        device({ hostname: 'NO-TAG' }),
      ]),
    );
    render(<DevicesView />);
    const found = (await screen.findByText('NUC-ASP-PRKNG')).closest('tr') as HTMLElement;
    expect(within(found).getByText('Discovered on network')).toBeInTheDocument();
    expect(within(screen.getByText('MANAGED-PC').closest('tr') as HTMLElement).queryByText('Discovered on network')).not.toBeInTheDocument();
    expect(within(screen.getByText('NO-TAG').closest('tr') as HTMLElement).queryByText('Discovered on network')).not.toBeInTheDocument();
  });

  it('flags a device the master tool does not report, and the tally counts it', async () => {
    listMock.mockResolvedValue(
      list([device({ hostname: 'ONLY-ADDIGY', in_master: false, sources: [{ vendor: 'addigy', name: 'x', last_seen: NOW }] })], {
        master_vendor: 'ninjaone',
        summary: { total: 5, not_in_master: 1 },
      }),
    );
    render(<DevicesView />);
    expect(await screen.findByText('Not in NinjaOne', { selector: 'span' })).toBeInTheDocument();
    expect(screen.getByTestId('devices-gaps')).toHaveTextContent('1');
  });

  it('the gap card narrows the list to devices missing from the master', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'A' })], { master_vendor: 'ninjaone', summary: { total: 5, not_in_master: 1 } }));
    render(<DevicesView />);
    await screen.findByText('A');
    await userEvent.click(screen.getByRole('button', { name: /Not in NinjaOne/ }));
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ notInMaster: true })));
  });

  it('choosing a master tool saves it and reloads', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'A' })]));
    render(<DevicesView />);
    await screen.findByText('A');
    await userEvent.selectOptions(screen.getByLabelText('Master device list'), 'ninjaone');
    await waitFor(() => expect(masterMock).toHaveBeenCalledWith('ninjaone'));
    expect(listMock.mock.calls.length).toBeGreaterThan(1);
  });

  it('filters by client and by tool through the API', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'A' })]));
    render(<DevicesView />);
    await screen.findByText('A');
    await userEvent.selectOptions(await screen.findByLabelText('Client'), 'c1');
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ clientId: 'c1' })));
    await userEvent.selectOptions(screen.getByLabelText('Reported by'), 'addigy');
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ vendor: 'addigy', clientId: 'c1' })));
  });

  it('remembers the filters picked and opens the list that way next time', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'A' })]));
    const first = render(<DevicesView />);
    await screen.findByText('A');
    await userEvent.selectOptions(await screen.findByLabelText('Client'), 'c1');
    await userEvent.selectOptions(screen.getByLabelText('Reported by'), 'addigy');
    first.unmount();
    listMock.mockClear();
    render(<DevicesView />);
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ clientId: 'c1', vendor: 'addigy' })));
    expect(screen.getByLabelText('Client')).toHaveValue('c1');
  });

  it('opens unfiltered when nothing was saved or the saved value is rubbish', async () => {
    window.localStorage.setItem('aisoc.filters.devices', JSON.stringify({ missing: 'bogus', offlineOnly: 'yes', vendor: 7 }));
    listMock.mockResolvedValue(list([device({ hostname: 'A' })]));
    render(<DevicesView />);
    await screen.findByText('A');
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ missing: undefined, offline: undefined, vendor: undefined })));
  });

  it('filters by operating system through the API and remembers the choice', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'MAC-1', os: 'macOS 14' })]));
    render(<DevicesView />);
    await screen.findByText('MAC-1');
    await userEvent.selectOptions(screen.getByLabelText('Operating system'), 'mac');
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ os: 'mac' })));
    expect(JSON.parse(window.localStorage.getItem('aisoc.filters.devices') ?? '{}').os).toBe('mac');
    expect([...screen.getByLabelText('Operating system').querySelectorAll('option')].map((o) => o.textContent)).toEqual(['Any OS', 'Windows', 'Mac', 'iOS / iPadOS', 'Linux']);
  });

  it('a link that names filters opens the list already filtered, whatever was saved', async () => {
    window.localStorage.setItem('aisoc.filters.devices', JSON.stringify({ vendor: 'addigy', os: 'linux' }));
    routerParams.current = new URLSearchParams('client=c1&attention=1');
    listMock.mockResolvedValue(list([device({ hostname: 'A' })]));
    render(<DevicesView />);
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ clientId: 'c1', attention: true })));
    expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ vendor: undefined, os: undefined }));
    routerParams.current = new URLSearchParams('');
  });

  it('opening a row lists each feeding tool and the name it uses', async () => {
    listMock.mockResolvedValue(
      list([device({ hostname: 'MAC-1', model: 'MacBook Pro', sources: [{ vendor: 'addigy', name: 'Hals-MacBook', last_seen: NOW }] })]),
    );
    render(<DevicesView />);
    await userEvent.click(await screen.findByText('MAC-1'));
    expect(screen.getByText('Feeding this device')).toBeInTheDocument();
    expect(screen.getByText('as “Hals-MacBook”')).toBeInTheDocument();
    expect(screen.getByText('MacBook Pro')).toBeInTheDocument();
  });

  it('shows the failure instead of an empty table', async () => {
    listMock.mockRejectedValue(new Error('boom'));
    render(<DevicesView />);
    expect(await screen.findByRole('alert')).toHaveTextContent('boom');
  });

  it('without a client list (no clients) the client picker is not shown', async () => {
    childrenMock.mockResolvedValue([]);
    listMock.mockResolvedValue(list([device({ hostname: 'A' })]));
    render(<DevicesView />);
    await screen.findByText('A');
    expect(screen.queryByLabelText('Client')).toBeNull();
  });
});

describe('specs', () => {
  it('shows memory, processor and disks from the feed that reports them', () => {
    const d = device({ hostname: 'H',
      sources: [
        { vendor: 'addigy', name: 'x', last_seen: NOW },
        { vendor: 'ninjaone', name: 'x', last_seen: NOW, details: { memory_gb: 16, processor: 'Intel i7', cpu_cores: 4, disks: [{ name: 'C:', size_gb: 511, free_gb: 120 }] } },
      ],
    });
    expect(specs(d)).toEqual([
      ['Memory', '16 GB'],
      ['Processor', 'Intel i7 (4 cores)'],
      ['Disks', 'C: 511 GB (120 free)'],
    ]);
  });

  it('shows nothing when no feed reports specs', () => {
    expect(specs(device({ hostname: 'H' }))).toEqual([]);
  });
});

describe('facts', () => {
  it('turns reported fields into readable labels and values', () => {
    const src = { vendor: 'ninjaone', name: 'x', last_seen: NOW, details: { facts: { nodeClass: 'WINDOWS_LAPTOP', 'os.buildNumber': 26300, offline: false } } };
    expect(facts(src)).toEqual([
      ['Node class', 'WINDOWS_LAPTOP'],
      ['Os build number', '26300'],
      ['Offline', 'false'],
    ]);
  });

  it('is empty when the feed sent no facts', () => {
    expect(facts({ vendor: 'addigy', name: 'x', last_seen: NOW })).toEqual([]);
  });
});

describe('missing-from-tool cards', () => {
  it('shows how many devices each tool is missing and filters to them when clicked', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'MAC-1' })], { summary: { total: 5, not_in_master: 0, not_in_addigy: 2, not_in_threatmate: 4 } }));
    render(<DevicesView />);
    await screen.findByText('MAC-1');
    expect(screen.getByTestId('devices-missing-addigy')).toHaveTextContent('2');
    expect(screen.getByTestId('devices-missing-threatmate')).toHaveTextContent('4');
    expect(screen.getByText(/Not in Addigy/)).toHaveTextContent('Macs');

    await userEvent.click(screen.getByRole('button', { name: /Not in ThreatMate/ }));
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ missing: 'threatmate' })));

    await userEvent.click(screen.getByRole('button', { name: /Not in ThreatMate/ }));
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ missing: undefined })));
  });

  it('shows how many open alerts name a device, and lists them when the row is opened', async () => {
    listMock.mockResolvedValue(
      list([
        device({
          hostname: 'FRONT-DESK',
          open_alerts: 2,
          alerts: [
            { id: 'a1', title: 'Disk space low', severity: 'high', status: 'new', source: 'ninjaone', created_at: NOW },
            { id: 'a2', title: 'Patch failed', severity: 'low', status: 'new', source: 'ninjaone', created_at: NOW },
          ],
        }),
        device({ hostname: 'QUIET-PC' }),
      ]),
    );
    render(<DevicesView />);
    const row = (await screen.findByText('FRONT-DESK')).closest('tr') as HTMLElement;
    expect(within(row).getByText('2 open alerts')).toBeInTheDocument();
    expect(within(row).getByRole('link', { name: '2 open alerts' })).toHaveAttribute('href', '/alerts?device=FRONT-DESK');
    const quiet = screen.getByText('QUIET-PC').closest('tr') as HTMLElement;
    expect(within(quiet).queryByText(/open alert/)).not.toBeInTheDocument();
    await userEvent.setup().click(row);
    expect(screen.getByRole('link', { name: 'Disk space low' })).toHaveAttribute('href', '/alerts/a1');
    expect(screen.getByRole('link', { name: 'Patch failed' })).toBeInTheDocument();
  });

  it('has a Last online column separate from Last synced, and shows a dash when no tool says', async () => {
    listMock.mockResolvedValue(
      list([device({ hostname: 'ONLINE-PC', last_online: '2020-01-02T03:04:05Z' }), device({ hostname: 'NO-IDEA' })]),
    );
    render(<DevicesView />);
    await screen.findByText('ONLINE-PC');
    expect(screen.getByRole('columnheader', { name: 'Last online' })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Last synced' })).toBeInTheDocument();
    const cells = (name: string) => within((screen.getByText(name).closest('tr')) as HTMLElement).getAllByRole('cell');
    expect(cells('ONLINE-PC')[5].textContent).toMatch(/2020/);
    expect(cells('NO-IDEA')[5]).toHaveTextContent('—');
  });

  it('marks a device that has been offline for days, and the tiles filter by offline and by open alerts', async () => {
    listMock.mockResolvedValue(
      list([device({ hostname: 'GONE-PC', last_online: '2020-01-02T03:04:05Z', offline_days: 40 })], { summary: { total: 5, not_in_master: 0, offline: 3, with_alerts: 2 } }),
    );
    render(<DevicesView />);
    const row = (await screen.findByText('GONE-PC')).closest('tr') as HTMLElement;
    expect(within(row).getByText('Offline 40d')).toBeInTheDocument();
    expect(screen.getByTestId('devices-offline')).toHaveTextContent('3');
    expect(screen.getByTestId('devices-alerts')).toHaveTextContent('2');
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /Offline 7\+ days/ }));
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ offline: true })));
    await user.click(screen.getByRole('button', { name: /With open alerts/ }));
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ offline: true, hasAlerts: true })));
  });

  it('shows a dot for online or offline when a tool says, and none when no tool does', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'UP-PC', online: true }), device({ hostname: 'DOWN-PC', online: false }), device({ hostname: 'UNKNOWN-PC' })]));
    render(<DevicesView />);
    const row = async (name: string) => (await screen.findByText(name)).closest('tr') as HTMLElement;
    expect(within(await row('UP-PC')).getByRole('img', { name: 'Online' })).toBeInTheDocument();
    expect(within(await row('DOWN-PC')).getByRole('img', { name: 'Offline' })).toBeInTheDocument();
    expect(within(await row('UNKNOWN-PC')).queryByRole('img', { name: /line/ })).toBeNull();
  });
});

describe('what a tool says needs attention', () => {
  it('collects the problems every source reports and ignores anything that is not a list of words', () => {
    const d = device({
      hostname: 'WS-01',
      sources: [
        { vendor: 'huntress', name: 'WS-01', last_seen: NOW, details: { needs_attention: ['Defender: Unhealthy', ''] } },
        { vendor: 'ninjaone', name: 'WS-01', last_seen: NOW, details: { needs_attention: 'nope' } },
      ],
    });
    expect(attentionOf(d)).toEqual(['Defender: Unhealthy']);
    expect(attentionOf(device({ hostname: 'CLEAN' }))).toEqual([]);
  });

  it('asks only for devices with a reported problem when the Needs attention card is picked', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'WS-01' })], { summary: { total: 1, not_in_master: 0, needs_attention: 3 } }));
    render(<DevicesView />);
    await waitFor(() => expect(screen.getByTestId('devices-attention')).toHaveTextContent('3'));
    await userEvent.setup().click(screen.getByRole('button', { name: /Needs attention/ }));
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ attention: true })));
  });
});

describe('clearer rows and messages', () => {
  it('says why a device needs attention, right in the list, with how many more reasons there are', async () => {
    listMock.mockResolvedValue(
      list([
        device({ hostname: 'WS-01', sources: [{ vendor: 'huntress', name: 'WS-01', last_seen: NOW, details: { needs_attention: ['Defender: Unhealthy', 'Tamper protection is configured but not in force'] } }] }),
        device({ hostname: 'CLEAN' }),
      ]),
    );
    render(<DevicesView />);
    const row = (await screen.findByText('WS-01')).closest('tr') as HTMLElement;
    expect(within(row).getByTestId('attention-reason')).toHaveTextContent('Defender: Unhealthy (+1 more)');
    expect(within(screen.getByText('CLEAN').closest('tr') as HTMLElement).queryByTestId('attention-reason')).not.toBeInTheDocument();
  });

  it('marks a device with a ransomware-linked vulnerability', async () => {
    const d = device({ hostname: 'RW-1', sources: [{ vendor: 'threatmate', name: 'RW-1', last_seen: NOW, details: { kev_ransomware: true } }] });
    expect(ransomwareLinked(d)).toBe(true);
    expect(ransomwareLinked(device({ hostname: 'OK' }))).toBe(false);
    listMock.mockResolvedValue(list([d]));
    render(<DevicesView />);
    expect(await screen.findByText('Ransomware-linked CVE')).toBeInTheDocument();
  });

  it('shows a loading message while the first load runs, instead of an empty table', async () => {
    listMock.mockReturnValue(new Promise(() => {}));
    render(<DevicesView />);
    expect(await screen.findByTestId('devices-loading')).toHaveTextContent('Loading devices');
  });

  it('explains a failed load with the API reason and offers to try again', async () => {
    listMock.mockRejectedValueOnce(Object.assign(new Error('API 500 Internal Server Error'), { status: 500 }));
    listMock.mockResolvedValue(list([device({ hostname: 'BACK-AGAIN' })]));
    render(<DevicesView />);
    const alertBox = await screen.findByRole('alert');
    expect(alertBox).toHaveTextContent('Could not load devices (error 500)');
    expect(alertBox).toHaveTextContent('Platform health');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('BACK-AGAIN')).toBeInTheDocument();
  });

  it('builds the message from the status and the reason', () => {
    expect(devicesLoadError(Object.assign(new Error('boom'), { status: 502 }))).toMatch(/^Could not load devices \(error 502\): boom\./);
    expect(devicesLoadError('???')).toMatch(/^Could not load devices\. Try again/);
  });
});

describe('stale agents', () => {
  it('shows how many agents have gone quiet and asks only for those when the card is picked', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'OLD-1' })], { summary: { total: 1, not_in_master: 0, stale_agents: 7 } }));
    render(<DevicesView />);
    await waitFor(() => expect(screen.getByTestId('devices-stale')).toHaveTextContent('7'));
    await userEvent.setup().click(screen.getByRole('button', { name: /Stale agents/ }));
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ stale: true })));
  });
});

describe('protection in plain words', () => {
  const hd = (details: Record<string, unknown>) => device({ hostname: 'WS-01', sources: [{ vendor: 'huntress', name: 'WS-01', last_seen: NOW, details }] });

  it('states Defender, the firewall, tamper protection and the last check-in plainly', () => {
    const lines = protectionLines(
      hd({ defender_status: 'Unhealthy', defender_substatus: 'Real-time off', defender_policy_status: 'Non Compliant', firewall_status: 'Disabled', tamper_protection_configured: true, tamper_protection_actual: false, days_since_checkin: 20, edr_version: '1.2' }),
    );
    expect(Object.fromEntries(lines)).toEqual({
      'Microsoft Defender': 'Unhealthy (Real-time off)',
      'Defender policy': 'Non Compliant',
      'Windows firewall': 'Disabled',
      'Tamper protection': 'Configured, but NOT in force',
      'Huntress agent checked in': '20 days ago',
      'Huntress version': '1.2',
    });
  });

  it('says in force when it is, not configured when it is not, and today for a fresh agent', () => {
    expect(Object.fromEntries(protectionLines(hd({ tamper_protection_configured: true, tamper_protection_actual: true, days_since_checkin: 0 })))).toEqual({ 'Tamper protection': 'On, and in force', 'Huntress agent checked in': 'today' });
    expect(Object.fromEntries(protectionLines(hd({ tamper_protection_configured: false })))).toEqual({ 'Tamper protection': 'Not configured' });
  });

  it('shows nothing for a device Huntress does not report, and nothing is invented for missing fields', () => {
    expect(protectionLines(device({ hostname: 'NO-HUNTRESS' }))).toEqual([]);
    expect(protectionLines(hd({}))).toEqual([]);
  });

  it('appears in the expanded row', async () => {
    listMock.mockResolvedValue(list([hd({ defender_status: 'Healthy', days_since_checkin: 2 })]));
    render(<DevicesView />);
    await userEvent.setup().click(await screen.findByText('WS-01'));
    const panel = await screen.findByTestId('protection');
    expect(panel).toHaveTextContent('Microsoft Defender');
    expect(panel).toHaveTextContent('2 days ago');
  });
});

describe('hiding an offline device until it checks back in', () => {
  it('hides it from the row, then reloads the list', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'GLF-L02', last_online: '2026-09-28T00:00:00Z', offline_days: 21 })]));
    render(<DevicesView />);
    const row = (await screen.findByText('GLF-L02')).closest('tr') as HTMLElement;
    await userEvent.click(within(row).getByRole('button', { name: 'Hide until online' }));
    expect(hideMock).toHaveBeenCalledWith('d-GLF-L02');
    await waitFor(() => expect(listMock.mock.calls.length).toBeGreaterThan(1));
  });

  it('offers no hide button for a device that is not offline', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'ONLINE-1', offline_days: null })]));
    render(<DevicesView />);
    const row = (await screen.findByText('ONLINE-1')).closest('tr') as HTMLElement;
    expect(within(row).queryByRole('button', { name: 'Hide until online' })).not.toBeInTheDocument();
  });

  it('shows hidden devices with a Show again button, and the count on the card', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'GLF-L03', offline_days: 58, hidden_since: NOW })], { summary: { total: 5, not_in_master: 0, hidden: 1 } }));
    render(<DevicesView />);
    const row = (await screen.findByText('GLF-L03')).closest('tr') as HTMLElement;
    expect(screen.getByTestId('devices-hidden')).toHaveTextContent('1');
    await userEvent.click(within(row).getByRole('button', { name: 'Show again' }));
    expect(unhideMock).toHaveBeenCalledWith('d-GLF-L03');
  });

  it('asks the API for hidden devices when the card is pressed', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'A' })]));
    render(<DevicesView />);
    await screen.findByText('A');
    await userEvent.click(screen.getByRole('button', { name: /Hidden until online/ }));
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ hidden: true })));
  });
});

describe('devices offline for a month', () => {
  it('says how many are left out of the other numbers', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'A' })], { summary: { total: 3, not_in_master: 0, long_offline: 2 } }));
    render(<DevicesView />);
    expect(await screen.findByTestId('long-offline-note')).toHaveTextContent('2 devices offline for 10 days or more');
  });

  it('says nothing when there are none', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'B' })], { summary: { total: 1, not_in_master: 0, long_offline: 0 } }));
    render(<DevicesView />);
    await screen.findByText('B');
    expect(screen.queryByTestId('long-offline-note')).not.toBeInTheDocument();
  });
});

describe('Show alerts button', () => {
  it('opens the alerts page on every alert about the device, from the expanded row', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'GLF10-002D', open_alerts: 2 })]));
    render(<DevicesView />);
    await userEvent.click(await screen.findByText('GLF10-002D'));
    const link = screen.getByRole('link', { name: 'Show alerts (2 open)' });
    expect(link).toHaveAttribute('href', '/alerts?device=GLF10-002D&status=all');
  });

  it('is there even when the device has no open alerts', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'QUIET-1' })]));
    render(<DevicesView />);
    await userEvent.click(await screen.findByText('QUIET-1'));
    expect(screen.getByRole('link', { name: 'Show alerts' })).toHaveAttribute('href', '/alerts?device=QUIET-1&status=all');
  });
});

describe('opening from a link with ?search=', () => {
  it('starts filtered on the device named in the address the ROUTER gives (window.location lags during a client-side navigation)', async () => {
    routerParams.current = new URLSearchParams('search=Mac');
    try {
      listMock.mockResolvedValue(list([device({ hostname: 'Mac' })]));
      render(<DevicesView />);
      await waitFor(() => expect(listMock).toHaveBeenCalledWith(expect.objectContaining({ search: 'Mac' })));
      expect((screen.getByPlaceholderText(/Search name, serial or client/i) as HTMLInputElement).value).toBe('Mac');
    } finally {
      routerParams.current = new URLSearchParams('');
    }
  });
});

describe('filtersFromParams', () => {
  it('reads the filters a link names, and nothing from an ordinary address', () => {
    expect(filtersFromParams(new URLSearchParams('client=c1&attention=1&stale=1&offline=1&alerts=1&missing=huntress&os=mac&tool=huntress'))).toEqual({
      clientId: 'c1',
      vendor: 'huntress',
      os: 'mac',
      missing: 'huntress',
      attentionOnly: true,
      staleOnly: true,
      offlineOnly: true,
      alertsOnly: true,
    });
    expect(filtersFromParams(new URLSearchParams('search=PC-1'))).toBeNull();
    expect(filtersFromParams(null)).toBeNull();
    expect(filtersFromParams(new URLSearchParams('missing=bogus'))).toBeNull();
  });
});
