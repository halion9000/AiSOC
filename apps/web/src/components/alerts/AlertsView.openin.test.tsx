import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AlertRow } from './AlertsView';
import type { Alert } from '@/lib/api';

const alert = (over: Partial<Alert> = {}) =>
  ({ id: 'a1', title: 'Unexpected Country - Croatia', description: '', severity: 'high', status: 'new', source: 'huntress', tenantId: 't', riskScore: 5, createdAt: '2026-10-21T10:00:00Z', ...over }) as unknown as Alert;

afterEach(() => vi.restoreAllMocks());

describe('the alert row: Open in the tool that raised it', () => {
  it('shows "Open in Huntress" when the alert carries the tool\'s own address, and opens it in a new tab without selecting the row', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    const onSelect = vi.fn();
    render(<AlertRow alert={alert({ sourceUrl: 'https://goliveoak.huntress.io/account/infection_reports/1847944' })} selected={false} onSelect={onSelect} />);
    const link = screen.getByTestId('alert-open-in-tool');
    expect(link).toHaveTextContent('Open in Huntress');
    await userEvent.click(link);
    expect(open).toHaveBeenCalledWith('https://goliveoak.huntress.io/account/infection_reports/1847944', '_blank', 'noopener,noreferrer');
    expect(onSelect).not.toHaveBeenCalled();
  });

  it('can be used from the keyboard', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    render(<AlertRow alert={alert({ source: 'blumira', sourceUrl: 'https://app.blumira.com/x/query/findings/1' })} selected={false} onSelect={vi.fn()} />);
    screen.getByTestId('alert-open-in-tool').focus();
    await userEvent.keyboard('{Enter}');
    expect(open).toHaveBeenCalledTimes(1);
  });

  it('shows nothing when there is no address, or one that is not a plain https address', () => {
    for (const sourceUrl of [undefined, '', 'javascript:alert(1)', 'http://insecure.example/x', 'ftp://x/y']) {
      const { unmount } = render(<AlertRow alert={alert({ sourceUrl })} selected={false} onSelect={vi.fn()} />);
      expect(screen.queryByTestId('alert-open-in-tool')).not.toBeInTheDocument();
      unmount();
    }
  });
});
