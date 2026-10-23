import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

const state = vi.hoisted(() => ({ path: '/dashboard', hidden: new Set<string>() }));
vi.mock('next/navigation', () => ({ usePathname: () => state.path }));
vi.mock('next/link', () => ({
  default: ({ children, href, className }: { children: React.ReactNode; href: string; className?: string }) => (
    <a href={href} className={className}>
      {children}
    </a>
  ),
}));
vi.mock('@/hooks/useHiddenNav', () => ({ useHiddenNav: () => state.hidden }));

import { Sidebar } from './Sidebar';
import { HiddenPageGuard } from './HiddenPageGuard';

beforeEach(() => {
  state.path = '/dashboard';
  state.hidden = new Set();
});

describe('the sidebar for a role that hides things', () => {
  it('shows everything when nothing is hidden', () => {
    render(<Sidebar />);
    expect(screen.getByRole('link', { name: /Playbooks/ })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Multi-Factor/ })).toBeInTheDocument();
    expect(screen.getByText('Automation')).toBeInTheDocument();
  });

  it('takes out a whole hidden section, title included', () => {
    state.hidden = new Set(['section:Automation']);
    render(<Sidebar />);
    expect(screen.queryByText('Automation')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Playbooks/ })).not.toBeInTheDocument();
    expect(screen.getByText('Client Security')).toBeInTheDocument();
  });

  it('takes out one sub-page and leaves the rest of its section', () => {
    state.hidden = new Set(['/settings/client-posture']);
    render(<Sidebar />);
    expect(screen.queryByRole('link', { name: /Client Posture/ })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Multi-Factor/ })).toBeInTheDocument();
    expect(screen.getByText('Client Security')).toBeInTheDocument();
  });

  it('keeps the roles page even when its section is hidden', () => {
    state.hidden = new Set(['section:Platform']);
    render(<Sidebar />);
    expect(screen.getByRole('link', { name: /Roles/ })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Connectors/ })).not.toBeInTheDocument();
  });
});

describe('opening the address of a hidden page', () => {
  it('shows the page when it is allowed', () => {
    state.path = '/playbooks';
    render(
      <HiddenPageGuard>
        <p>the playbooks page</p>
      </HiddenPageGuard>,
    );
    expect(screen.getByText('the playbooks page')).toBeInTheDocument();
  });

  it('says the role hides it instead of showing the page, for the page or anything under it', () => {
    state.hidden = new Set(['section:Automation']);
    for (const path of ['/playbooks', '/playbooks/abc']) {
      state.path = path;
      const { unmount } = render(
        <HiddenPageGuard>
          <p>the playbooks page</p>
        </HiddenPageGuard>,
      );
      expect(screen.queryByText('the playbooks page')).not.toBeInTheDocument();
      expect(screen.getByRole('status')).toHaveTextContent('hidden for your role');
      unmount();
    }
  });

  it('never hides the dashboard', () => {
    state.hidden = new Set(['/dashboard', 'section:Automation']);
    render(
      <HiddenPageGuard>
        <p>home</p>
      </HiddenPageGuard>,
    );
    expect(screen.getByText('home')).toBeInTheDocument();
  });
});
