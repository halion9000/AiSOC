import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

// Mock Next.js routing primitives. The Sidebar reads `usePathname` to decide
// which item is active and uses `<Link>` for navigation; for a smoke test we
// just need both to behave as plain functions/elements.
vi.mock('next/navigation', () => ({
  usePathname: () => '/dashboard',
}));

vi.mock('next/link', () => ({
  default: ({
    children,
    href,
    className,
  }: {
    children: React.ReactNode;
    href: string;
    className?: string;
  }) => (
    <a href={href} className={className}>
      {children}
    </a>
  ),
}));

import { Sidebar } from './Sidebar';

describe('Sidebar', () => {
  it('renders the A.C.O.R.N mark and the major nav sections', () => {
    render(<Sidebar />);

    // Brand
    expect(screen.getByText('A.C.')).toBeInTheDocument();
    expect(screen.getByText('O.R.N')).toBeInTheDocument();

    // Section headings — Dashboard sits in an unlabelled lead section,
    // everything else is grouped under one of these four titles.
    expect(screen.getByText('Threat Operations')).toBeInTheDocument();
    expect(screen.getByText('Intelligence')).toBeInTheDocument();
    expect(screen.getByText('Automation')).toBeInTheDocument();
    expect(screen.getByText('Platform')).toBeInTheDocument();
  });

  it('exposes the marketplace and compliance entry points', () => {
    render(<Sidebar />);

    const marketplace = screen.getByRole('link', { name: /marketplace/i });
    expect(marketplace).toHaveAttribute('href', '/marketplace');

    const compliance = screen.getByRole('link', { name: /compliance/i });
    expect(compliance).toHaveAttribute('href', '/compliance');
  });

  it('has a Client Security section with the client posture, Multi-Factor, sign-in scores, cleanup and platform health pages', () => {
    const { container } = render(<Sidebar />);
    expect(screen.getByText('Client Security')).toBeInTheDocument();
    const hrefs = [...container.querySelectorAll('a')].map((a) => a.getAttribute('href'));
    for (const h of ['/settings/client-posture', '/settings/mfa', '/settings/signin-scores', '/settings/client-cleanup', '/settings/platform-health']) expect(hrefs).toContain(h);
  });

  it('renders the MIT license attribution in the footer', () => {
    render(<Sidebar />);

    const license = screen.getByRole('link', { name: /MIT License/i });
    expect(license).toHaveAttribute('href', 'https://github.com/beenuar/AiSOC');
  });
});

describe('Sidebar wordmark', () => {
  it('is one colour all the way through, with the full name underneath', () => {
    render(<Sidebar />);
    const a = screen.getByText('A.C.');
    const b = screen.getByText('O.R.N');
    const colour = (el: HTMLElement) => (el.className.match(/text-[a-z]+-\d+/) ?? [''])[0];
    expect(colour(a)).toBe(colour(b));
    expect(colour(a)).not.toBe('');
    expect(screen.getByText('Automated Cyber Operations & Response Network')).toBeInTheDocument();
    expect(screen.queryByText('open-source')).toBeNull();
  });
});
