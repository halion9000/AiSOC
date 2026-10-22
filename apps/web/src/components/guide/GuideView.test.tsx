import { describe, expect, it } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { GuideView } from './GuideView';

describe('GuideView', () => {
  it('shows the title, the status note and every section with a contents link', () => {
    render(<GuideView />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('A.C.O.R.N and CORE: how to use them');
    expect(screen.getByTestId('guide-note')).toHaveTextContent('Reading the status notes');
    const contents = screen.getByRole('navigation', { name: 'Guide contents' });
    expect(within(contents).getAllByRole('link')).toHaveLength(15);
    expect(screen.getAllByRole('heading', { level: 2 })).toHaveLength(15);
  });

  it('renders tables as tables and the (new) tags as badges, not as raw text', () => {
    const { container } = render(<GuideView />);
    expect(container.querySelectorAll('table')).toHaveLength(2);
    const badges = [...container.querySelectorAll('span')].filter((s) => /^new\b/.test(s.textContent ?? '') && s.className.includes('emerald'));
    expect(badges.length).toBeGreaterThan(5);
    expect(container.textContent).not.toContain('**');
    expect(container.textContent).not.toContain('|---');
  });

  it('narrows the sections as you search, and says so when nothing matches', async () => {
    render(<GuideView />);
    await userEvent.type(screen.getByLabelText('Search the guide'), 'hidden until online');
    const headings = screen.getAllByRole('heading', { level: 2 });
    expect(headings.length).toBeLessThan(15);
    expect(headings.map((h) => h.textContent).join(' ')).toContain('Devices');
    await userEvent.clear(screen.getByLabelText('Search the guide'));
    await userEvent.type(screen.getByLabelText('Search the guide'), 'zzzz-not-in-the-guide');
    expect(screen.getByTestId('guide-none')).toHaveTextContent('Nothing in the guide mentions');
  });
});
