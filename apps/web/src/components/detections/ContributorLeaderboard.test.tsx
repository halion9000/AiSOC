import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ContributorLeaderboard } from './ContributorLeaderboard';

describe('ContributorLeaderboard', () => {
  it('explains the four badge tiers and what each needs', () => {
    render(<ContributorLeaderboard />);
    for (const [label, need] of [['Platinum', '50+ rules'], ['Gold', '20+ rules'], ['Silver', '10+ rules'], ['Bronze', '1+ rules']]) {
      const tile = screen.getAllByText(label)[0].parentElement as HTMLElement;
      expect(tile).toHaveTextContent(need);
    }
  });

  it('lists the contributor with rank, badge, categories and rule count', () => {
    render(<ContributorLeaderboard />);
    const row = screen.getByText('A.C.O.R.N', { selector: 'span.truncate' }).closest('div.rounded-lg') as HTMLElement;
    expect(row).toHaveTextContent('1');
    expect(row).toHaveTextContent('Platinum');
    expect(row).toHaveTextContent('218');
    for (const cat of ['cloud', 'endpoint', 'identity', 'network', 'application']) expect(row).toHaveTextContent(cat);
  });

  it('shows the corpus total with the number of distinct categories', () => {
    render(<ContributorLeaderboard />);
    expect(screen.getByText(/218\+ rules across 5 categories/)).toBeInTheDocument();
  });

  it('invites contributions while the board has one entry or fewer', () => {
    render(<ContributorLeaderboard />);
    expect(screen.getByText(/leaderboard grows as detection rule PRs are merged/)).toBeInTheDocument();
  });

  it('the links open in a new tab without handing over the opener', () => {
    render(<ContributorLeaderboard />);
    for (const link of screen.getAllByRole('link')) {
      expect(link).toHaveAttribute('target', '_blank');
      expect(link.getAttribute('rel')).toContain('noreferrer');
      expect(link.getAttribute('href')).toMatch(/^https:\/\/github\.com\//);
    }
    expect(screen.getByRole('link', { name: /Contribute a rule/ })).toBeInTheDocument();
  });

  it('can be sorted by rule count or by name without losing the entry', async () => {
    render(<ContributorLeaderboard />);
    await userEvent.click(screen.getByRole('button', { name: 'Name' }));
    expect(screen.getByText('A.C.O.R.N', { selector: 'span.truncate' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Rule count' }));
    expect(screen.getByText('A.C.O.R.N', { selector: 'span.truncate' })).toBeInTheDocument();
  });
});
