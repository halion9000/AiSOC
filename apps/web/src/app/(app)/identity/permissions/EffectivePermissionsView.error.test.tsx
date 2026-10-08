import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

// Cytoscape needs a real canvas; the failure paths under test draw nothing.
vi.mock('cytoscape', () => ({ __esModule: true, default: Object.assign(vi.fn(() => ({ destroy: vi.fn(), on: vi.fn(), layout: vi.fn(() => ({ run: vi.fn() })), fit: vi.fn(), elements: vi.fn() })), { use: vi.fn() }) }));
vi.mock('cytoscape-fcose', () => ({ __esModule: true, default: vi.fn() }));

const params = vi.hoisted(() => ({ value: new URLSearchParams('provider=aws&principal_id=alice') }));
vi.mock('next/navigation', () => ({ useSearchParams: () => params.value }));

const resolve = vi.hoisted(() => ({ state: { data: undefined as unknown, error: undefined as unknown, isLoading: false } }));
vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    if (typeof key === 'string' && key.endsWith('/effective-permissions/providers')) {
      return { data: { providers: [{ name: 'aws', coverage: 'live' }] }, error: undefined, isLoading: false, mutate: vi.fn() };
    }
    return { ...resolve.state, mutate: vi.fn() };
  },
}));

import { EffectivePermissionsView, resolveFailure } from './EffectivePermissionsView';

// When the resolver call failed, the side panel said "Failed to resolve - falling back to demo data." Nothing ever fell back; it was a false sentence on a screen an
// administrator uses to decide what a user can do. And the main pane, on the same failure, was the EMPTY GRAPH CANVAS: a blank dark pane, which reads as "this principal has
// nothing". A failed lookup now says what failed, in both places, and is never confused with an empty result.
const envelope = { provider: 'aws', principal_id: 'alice', coverage: 'live', resolver_version: 'v1.2.3', last_resolved: '2026-10-08T01:00:00Z', decisions: [], notes: [] as string[] };

beforeEach(() => {
  params.value = new URLSearchParams('provider=aws&principal_id=alice');
  resolve.state = { data: undefined, error: undefined, isLoading: false };
});

describe('when the resolver call fails', () => {
  it('says what failed in the side panel, with no demo claim', () => {
    resolve.state = { data: undefined, error: new Error('HTTP 500 resolver blew up'), isLoading: false };
    const { container } = render(<EffectivePermissionsView />);
    expect(screen.getByText('Failed to resolve: HTTP 500 resolver blew up.')).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo|falling back/i);
  });

  it('says so in the main pane too, and does not present a failed lookup as "no decisions"', () => {
    resolve.state = { data: undefined, error: new Error('HTTP 500 resolver blew up'), isLoading: false };
    render(<EffectivePermissionsView />);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent("Couldn't resolve this principal's permissions");
    expect(alert).toHaveTextContent('not an empty result');
    expect(screen.queryByText(/No decisions for this principal/)).not.toBeInTheDocument();
    expect(screen.queryByText(/The resolver returned zero decisions/)).not.toBeInTheDocument();
  });

  it('keeps the scaffolded-provider case as its own message, not a failure', () => {
    resolve.state = { data: undefined, error: new Error('HTTP 501 not implemented'), isLoading: false };
    const { container } = render(<EffectivePermissionsView />);
    expect(screen.getByRole('alert')).toHaveTextContent('This resolver is scaffolded: no live data yet');
    expect(container.textContent).not.toMatch(/Failed to resolve/);
  });
});

describe('when it does not fail', () => {
  it('says it is resolving while it loads, with no error', () => {
    resolve.state = { data: undefined, error: undefined, isLoading: true };
    render(<EffectivePermissionsView />);
    expect(screen.getByText(/Resolving/)).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows a genuinely empty result as empty, and the real envelope', () => {
    resolve.state = { data: envelope, error: undefined, isLoading: false };
    render(<EffectivePermissionsView />);
    expect(screen.getByText(/No decisions for this principal/)).toBeInTheDocument();
    expect(screen.getByText('v1.2.3')).toBeInTheDocument();
    expect(screen.queryByText(/Failed to resolve/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Couldn't resolve this principal/)).not.toBeInTheDocument();
  });
});

describe('the resolver\'s own notes', () => {
  it('shows a real note from the resolver, and nothing invented when there are none', () => {
    resolve.state = { data: { ...envelope, notes: ['Snapshot is 3 days old'] }, error: undefined, isLoading: false };
    const { unmount } = render(<EffectivePermissionsView />);
    expect(screen.getByText('Snapshot is 3 days old')).toBeInTheDocument();
    unmount();
    resolve.state = { data: envelope, error: undefined, isLoading: false };
    render(<EffectivePermissionsView />);
    expect(screen.queryByText('Snapshot is 3 days old')).not.toBeInTheDocument();
  });
});

describe('resolveFailure', () => {
  it('uses the real reason, and a plain fallback when there is none', () => {
    expect(resolveFailure(new Error('HTTP 503'))).toBe('HTTP 503');
    expect(resolveFailure(new Error(''))).toBe('the resolver is unreachable');
    expect(resolveFailure('weird')).toBe('the resolver is unreachable');
  });
});
