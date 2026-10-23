import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ catalog: vi.fn(), list: vi.fn() }));
const nav = vi.hoisted(() => ({ replace: vi.fn(), params: new URLSearchParams() }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));

vi.mock('@/lib/api', () => ({ connectorsApi: api }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ replace: nav.replace }), useSearchParams: () => nav.params }));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: toast }));
vi.mock('next/link', () => ({ default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => <a href={href} {...rest}>{children}</a> }));
vi.mock('framer-motion', () => ({ motion: { div: ({ children, className }: { children: React.ReactNode; className?: string }) => <div className={className}>{children}</div> } }));
// The wizard has its own tests; here it only shows what the page handed it.
vi.mock('@/components/connectors/AddConnectorModal', async () => {
  const actual = await vi.importActual<typeof import('@/components/connectors/AddConnectorModal')>('@/components/connectors/AddConnectorModal');
  return {
    CATEGORY_LABEL: actual.CATEGORY_LABEL,
    CATEGORY_ORDER: actual.CATEGORY_ORDER,
    MOST_TEAMS_PICK: actual.MOST_TEAMS_PICK,
    AddConnectorModal: ({ open, onClose, primedConnectorId, activeCategory, onCreated }: { open: boolean; onClose: () => void; primedConnectorId: string | null; activeCategory: string | null; onCreated: () => void }) =>
      open ? (
        <div data-testid="wizard">
          <span>primed:{primedConnectorId ?? 'none'}</span>
          <span>category:{activeCategory ?? 'none'}</span>
          <button onClick={onClose}>close wizard</button>
          <button onClick={onCreated}>created</button>
        </div>
      ) : null,
  };
});

import { OnboardingView } from './OnboardingView';

const entry = (id: string, name: string, category: string, extra: Record<string, unknown> = {}) => ({ connector_id: id, connector_name: name, category, description: `${name} events`, ...extra });
const CATALOG = [
  entry('crowdstrike', 'CrowdStrike Falcon', 'edr'),
  entry('okta', 'Okta', 'iam', { oauth: { supported_in_hosted: true } }),
  entry('splunk', 'Splunk', 'siem'),
  entry('obscure', 'Obscure Tool', 'edr'),
  entry('weird', 'Weird Tool', 'not-a-known-category'),
];

function renderView() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <OnboardingView />
    </SWRConfig>,
  );
}

beforeEach(() => {
  api.catalog.mockReset().mockResolvedValue({ connectors: CATALOG });
  api.list.mockReset().mockResolvedValue({ connectors: [] });
  nav.replace.mockReset();
  nav.params = new URLSearchParams();
  toast.success.mockReset();
  toast.error.mockReset();
});

describe('OnboardingView', () => {
  it('shows the welcome text straight away, and the counts only once the catalog is in', async () => {
    api.catalog.mockReturnValue(new Promise(() => {}));
    renderView();
    expect(screen.getByText('Connect your first security tool')).toBeInTheDocument();
    expect(screen.queryByText('Available')).toBeNull();
  });

  it('shows how many connector types exist, how many are connected, and how many send data', async () => {
    api.list.mockResolvedValue({ connectors: [{ id: '1', type: 'okta', status: 'active' }, { id: '2', type: 'splunk', status: 'pending' }] });
    renderView();
    const stat = async (label: string) => (await screen.findByText(label)).parentElement as HTMLElement;
    expect(within(await stat('Available')).getByText('5')).toBeInTheDocument();
    await waitFor(() => expect(within(screen.getByText('Connected', { selector: 'div' }).parentElement as HTMLElement).getByText('2')).toBeInTheDocument());
    expect(within(screen.getByText('Sending data').parentElement as HTMLElement).getByText('1')).toBeInTheDocument();
  });

  it('"Most teams pick" shows only curated connectors the catalog actually has, in the curated order', async () => {
    renderView();
    await screen.findByText('Most teams pick');
    const names = screen.getAllByTestId('tile-name').map((n) => n.textContent);
    expect(names).toEqual(['CrowdStrike Falcon', 'Okta', 'Splunk']);
  });

  it('marks tiles: OAuth one-click for a hosted OAuth connector, Connected for one already set up', async () => {
    api.list.mockResolvedValue({ connectors: [{ id: '1', type: 'crowdstrike', status: 'pending' }] });
    renderView();
    expect(await screen.findByText('OAuth one-click')).toBeInTheDocument();
    expect(await screen.findByText('Connected', { selector: 'span.inline-flex' })).toBeInTheDocument();
  });

  it('clicking a tile opens the wizard primed with that connector', async () => {
    renderView();
    await userEvent.click((await screen.findByText('Okta')).closest('button') as HTMLElement);
    expect(screen.getByTestId('wizard')).toHaveTextContent('primed:okta');
    expect(screen.getByTestId('wizard')).toHaveTextContent('category:none');
  });

  it('Browse all opens the wizard with nothing primed', async () => {
    renderView();
    await userEvent.click(await screen.findByRole('button', { name: /Browse all 5 connectors/ }));
    expect(screen.getByTestId('wizard')).toHaveTextContent('primed:none');
  });

  it('category buttons list only categories that have connectors, with counts, and open the wizard on that category', async () => {
    renderView();
    await screen.findByText('Or browse by category');
    const endpoint = screen.getByRole('button', { name: /Endpoint\s*2/ });
    expect(screen.getByRole('button', { name: /Identity\s*1/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /SIEM\s*1/ })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Cloud/ })).toBeNull();
    await userEvent.click(endpoint);
    expect(screen.getByTestId('wizard')).toHaveTextContent('category:edr');
  });

  it('closing the wizard clears what it was primed with, so the next open starts clean', async () => {
    renderView();
    await userEvent.click((await screen.findByText('Okta')).closest('button') as HTMLElement);
    await userEvent.click(screen.getByText('close wizard'));
    expect(screen.queryByTestId('wizard')).toBeNull();
    await userEvent.click(await screen.findByRole('button', { name: /Browse all/ }));
    expect(screen.getByTestId('wizard')).toHaveTextContent('primed:none');
    expect(screen.getByTestId('wizard')).toHaveTextContent('category:none');
  });

  it('once something is sending data it says so and links to cases, pluralised', async () => {
    api.list.mockResolvedValue({ connectors: [{ id: '1', type: 'okta', status: 'active' }] });
    renderView();
    expect(await screen.findByText(/events are flowing/)).toBeInTheDocument();
    expect(screen.getByText('1 connector sending data.', { exact: false })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open cases/ })).toHaveAttribute('href', '/cases');
  });

  it('a connector that has not sent data yet does not end onboarding', async () => {
    api.list.mockResolvedValue({ connectors: [{ id: '1', type: 'okta', status: 'pending' }] });
    renderView();
    await screen.findByText('Most teams pick');
    expect(screen.queryByText(/events are flowing/)).toBeNull();
  });

  it('says so when the catalog cannot be loaded', async () => {
    api.catalog.mockRejectedValue(new Error('down'));
    renderView();
    expect(await screen.findByText(/Failed to load connector catalog/)).toBeInTheDocument();
    expect(screen.queryByText('Most teams pick')).toBeNull();
  });

  it('links on to the docs (a different site, new tab) and to detections (in the app)', async () => {
    renderView();
    const docs = await screen.findByRole('link', { name: /Push-ingest docs/ });
    expect(docs).toHaveAttribute('target', '_blank');
    expect(docs).toHaveAttribute('rel', 'noopener noreferrer');
    expect(docs.getAttribute('href')).toMatch(/^https:\/\/.*operations\/credentials$/);
    const det = screen.getByRole('link', { name: /Open detections/ });
    expect(det).toHaveAttribute('href', '/detection');
    expect(det).not.toHaveAttribute('target');
  });

  it('coming back from a successful OAuth sign-in says which tool, reloads the list and cleans the address', async () => {
    nav.params = new URLSearchParams('oauth_success=1&connector_id=c9&connector_type=okta');
    renderView();
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Connected okta. Watching for live events…'));
    expect(nav.replace).toHaveBeenCalledWith('/onboarding');
    await waitFor(() => expect(api.list.mock.calls.length).toBeGreaterThanOrEqual(2));
  });

  it('a successful OAuth return without a tool name still says it worked', async () => {
    nav.params = new URLSearchParams('oauth_success=1');
    renderView();
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Connector OAuth complete.'));
  });

  it('a failed OAuth return shows the reason, or the code when there is none, and cleans the address', async () => {
    nav.params = new URLSearchParams('oauth_error=access_denied&oauth_message=You%20declined');
    const first = renderView();
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('OAuth failed: You declined', { duration: 8000 }));
    expect(nav.replace).toHaveBeenCalledWith('/onboarding');
    first.unmount();

    nav.params = new URLSearchParams('oauth_error=server_error');
    renderView();
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('OAuth failed (server_error). Check the connector logs.', { duration: 8000 }));
  });

  it('with no OAuth query nothing is shown or redirected', async () => {
    renderView();
    await screen.findByText('Most teams pick');
    expect(toast.success).not.toHaveBeenCalled();
    expect(toast.error).not.toHaveBeenCalled();
    expect(nav.replace).not.toHaveBeenCalled();
  });

  it('a connector created in the wizard reloads the connector list', async () => {
    renderView();
    await userEvent.click(await screen.findByRole('button', { name: /Browse all/ }));
    const before = api.list.mock.calls.length;
    await userEvent.click(screen.getByText('created'));
    await waitFor(() => expect(api.list.mock.calls.length).toBeGreaterThan(before));
  });
});
