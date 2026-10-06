import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RecentConversations } from './CopilotView';
import type { CopilotConversation } from '@/lib/api';

const convo = (n: number): CopilotConversation => ({
  id: `c${n}`,
  title: `Investigation ${n}`,
  updatedAt: '2026-10-06T00:00:00Z',
  messageCount: n,
});

const base = { isLoading: false, failed: false, conversations: [], onSelect: () => {} };

describe('RecentConversations', () => {
  it('a failed history request SAYS SO instead of promising history that cannot arrive', () => {
    // The API serves no /api/v1/copilot/conversations, so "Past conversations will appear here" was
    // never going to come true.
    render(<RecentConversations {...base} failed />);
    expect(screen.getByText(/history isn.t available in this build/i)).toBeInTheDocument();
    expect(screen.queryByText(/will appear here/i)).not.toBeInTheDocument();
  });

  it('a successful but empty history keeps the friendly empty state', () => {
    render(<RecentConversations {...base} />);
    expect(screen.getByText('Past conversations will appear here.')).toBeInTheDocument();
    expect(screen.queryByText(/isn.t available/i)).not.toBeInTheDocument();
  });

  it('shows skeletons while loading, and neither message', () => {
    const { container } = render(<RecentConversations {...base} isLoading />);
    expect(container.querySelectorAll('div > div').length).toBeGreaterThanOrEqual(3);
    expect(screen.queryByText(/will appear here/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/isn.t available/i)).not.toBeInTheDocument();
  });

  it('loading wins over a stale failure (a retry in flight must not flash an error)', () => {
    render(<RecentConversations {...base} isLoading failed />);
    expect(screen.queryByText(/isn.t available/i)).not.toBeInTheDocument();
  });

  it('lists conversations, highlights the selected one, and reports clicks', async () => {
    const onSelect = vi.fn();
    render(<RecentConversations {...base} conversations={[convo(1), convo(2)]} selectedId="c2" onSelect={onSelect} />);
    expect(screen.getByRole('button', { name: 'Investigation 2' }).className).toContain('bg-slate-800');
    expect(screen.getByRole('button', { name: 'Investigation 1' }).className).not.toContain('bg-slate-800 text-white');
    await userEvent.click(screen.getByRole('button', { name: 'Investigation 1' }));
    expect(onSelect).toHaveBeenCalledWith('c1');
  });

  it('shows at most the 8 most recent', () => {
    render(<RecentConversations {...base} conversations={Array.from({ length: 12 }, (_, i) => convo(i + 1))} />);
    expect(screen.getAllByRole('button')).toHaveLength(8);
  });

  it('a failed REFRESH never hides conversations that are already on screen', () => {
    // SWR keeps the old data AND sets the error when a revalidation fails.
    render(<RecentConversations {...base} failed conversations={[convo(1)]} />);
    expect(screen.getByRole('button', { name: 'Investigation 1' })).toBeInTheDocument();
    expect(screen.queryByText(/isn.t available/i)).not.toBeInTheDocument();
  });
});
