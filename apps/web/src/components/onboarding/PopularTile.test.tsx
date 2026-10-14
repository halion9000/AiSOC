import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';

vi.mock('next/link', () => ({ default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a> }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }));

import { PopularTile } from './OnboardingView';
import type { ConnectorCatalogEntry } from '@/lib/api';

const entry = (over: Partial<ConnectorCatalogEntry> = {}) =>
  ({
    connector_id: 'okta',
    connector_name: 'Okta',
    category: 'iam',
    description: 'Okta system log events',
    oauth: { supported_in_hosted: true },
    ...over,
  }) as unknown as ConnectorCatalogEntry;

describe('PopularTile', () => {
  it('shows the whole connector name and the OAuth badge, the badge below the name rather than beside it', () => {
    render(<PopularTile entry={entry({ connector_name: 'Okta Identity Cloud' })} onClick={() => {}} connected={false} />);
    const name = screen.getByTestId('tile-name');
    expect(name).toHaveTextContent('Okta Identity Cloud');
    // Not clipped to one line: a truncating name is what cut "Okta" down to "O…" next to the badge.
    expect(name.className).not.toMatch(/\btruncate\b|line-clamp|overflow-hidden/);
    const badge = screen.getByText('OAuth one-click');
    // The badge is not inside the name's own row, so it cannot take that row's width.
    expect(within(name).queryByText('OAuth one-click')).toBeNull();
    expect(name.parentElement).toBe(badge.parentElement);
    expect(name.compareDocumentPosition(badge) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('shows Connected instead of the OAuth badge once an instance exists, and nothing for a connector without OAuth', () => {
    const { unmount } = render(<PopularTile entry={entry()} onClick={() => {}} connected />);
    expect(screen.getByText('Connected')).toBeInTheDocument();
    expect(screen.queryByText('OAuth one-click')).toBeNull();
    unmount();
    render(<PopularTile entry={entry({ oauth: undefined })} onClick={() => {}} connected={false} />);
    expect(screen.queryByText('OAuth one-click')).toBeNull();
    expect(screen.queryByText('Connected')).toBeNull();
  });
});
