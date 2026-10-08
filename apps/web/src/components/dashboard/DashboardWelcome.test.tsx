import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// useSearchParams returns a STABLE object until the URL changes; a mock that returned a fresh one each render would re-run the component's effect and re-open the banner.
const nav = vi.hoisted(() => ({ params: new URLSearchParams('welcome=1'), replace: vi.fn() }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ replace: nav.replace }), useSearchParams: () => nav.params }));

import { DashboardWelcome } from './DashboardWelcome';

// The dashboard's welcome banner (shown to every new user) told them to "load the demo seed: run pnpm seed:demo", and its button opened /cases/INC-RT-001, a case that does not exist in a real workspace
// (it 404s as "Couldn't load case"). It also quoted counts nobody maintains ("26 vendors", "25 named runbooks").
beforeEach(() => {
  nav.params = new URLSearchParams('welcome=1');
  nav.replace.mockReset();
});

it('is hidden unless the onboarding flow asked for it', () => {
  nav.params = new URLSearchParams('');
  render(<DashboardWelcome />);
  expect(screen.queryByTestId('dashboard-welcome')).not.toBeInTheDocument();
});

describe('when shown', () => {
  it('suggests three real next steps and links only to pages that exist', () => {
    render(<DashboardWelcome />);
    const hrefs = screen.getAllByRole('link').map((a) => a.getAttribute('href'));
    expect(hrefs).toEqual(['/onboarding', '/detection', '/playbooks']);
    expect(screen.getByText('Connect a source')).toBeInTheDocument();
    expect(screen.getByText('Review detection rules')).toBeInTheDocument();
    expect(screen.getByText('Browse playbooks')).toBeInTheDocument();
  });

  it('does not tell anyone to load demo data or open a sample case', () => {
    const { container } = render(<DashboardWelcome />);
    expect(container.textContent).not.toMatch(/demo|seed|sample case|INC-RT-001|pnpm/i);
    expect(screen.queryByRole('link', { name: /sample case/i })).not.toBeInTheDocument();
  });

  it('quotes no hard-coded counts', () => {
    const { container } = render(<DashboardWelcome />);
    // no \b anchors: textContent glues neighbouring elements together ("Browse playbooks25 named..."), so a word boundary would never match
    expect(container.textContent).not.toMatch(/26 vendors|25 named/);
  });

  it('can be dismissed, and clears the query string', async () => {
    render(<DashboardWelcome />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Dismiss welcome message' }));
    expect(screen.queryByTestId('dashboard-welcome')).not.toBeInTheDocument();
    expect(nav.replace).toHaveBeenCalledTimes(1);
  });
});
