import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

vi.mock('@/components/landing/sections/StickyNav', () => ({ StickyNav: () => null }));
vi.mock('@/components/landing/sections/Footer', () => ({ Footer: () => null }));

import NotFoundPage, { metadata } from './not-found';

// The global 404 offered "Open the live dashboard: Anonymous, pre-seeded investigation. No signup. Demo data resets daily at 00:00 UTC." On a real deployment the dashboard needs a sign-in and holds
// no demo data, and the page's metadata advertised "the interactive demo".
describe('the 404 page', () => {
  it('says nothing about demo data, an anonymous pre-seeded investigation, or an interactive demo', () => {
    const { container } = render(<NotFoundPage />);
    expect(container.textContent).not.toMatch(/demo|pre-seeded|anonymous|no signup/i);
    expect(String(metadata.description)).not.toMatch(/demo/i);
  });

  it('still offers the dashboard, pricing, docs and contact, and a way home', () => {
    render(<NotFoundPage />);
    const hrefs = screen.getAllByRole('link').map((a) => a.getAttribute('href'));
    expect(hrefs).toEqual(expect.arrayContaining(['/', '/dashboard', '/pricing', '/contact']));
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('We do not have a page at that URL.');
    expect(screen.getByText('Your workspace: alerts, cases, and the metrics behind them.')).toBeInTheDocument();
  });

  it('is not indexed', () => {
    expect(metadata.robots).toEqual({ index: false, follow: false });
  });
});
