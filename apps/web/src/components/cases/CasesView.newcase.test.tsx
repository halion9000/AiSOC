import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ list: vi.fn(), counts: vi.fn() }));
vi.mock('@/lib/api', () => ({ casesApi: { list: api.list, counts: api.counts, create: vi.fn() } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@/components/saved-views/SavedViewsBar', () => ({ SavedViewsBar: () => null }));

import { CasesView } from './CasesView';

beforeEach(() => {
  api.list.mockReset();
  api.list.mockResolvedValue({ cases: [], total: 0 });
  api.counts.mockResolvedValue({ all: 0, open: 0, in_progress: 0, resolved: 0, closed: 0 });
});

describe('the New Case button', () => {
  it('is live, opens the create window, and the page no longer says it is planned', async () => {
    const user = userEvent.setup();
    const { container } = render(
      <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
        <CasesView />
      </SWRConfig>,
    );
    const button = await screen.findByRole('button', { name: /New Case/ });
    expect(button).toBeEnabled();
    expect(container.textContent).not.toMatch(/planned for v1\.1/i);
    await user.click(button);
    expect(screen.getByRole('dialog', { name: 'Create case' })).toBeInTheDocument();
  });
});
