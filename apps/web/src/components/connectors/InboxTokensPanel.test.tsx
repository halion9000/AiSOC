import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { InboxTemplate, InboxTokenListItem, InboxTokenSecret } from '@/lib/api';

const api = vi.hoisted(() => ({
  templates: vi.fn(),
  list: vi.fn(),
  mint: vi.fn(),
  rotate: vi.fn(),
  revoke: vi.fn(),
}));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));

vi.mock('@/lib/api', () => ({
  inboxApi: api,
  ApiError: class ApiError extends Error {
    status: number;
    body: string;
    constructor(message: string, status: number, body: string) {
      super(message);
      this.status = status;
      this.body = body;
    }
  },
}));
vi.mock('react-hot-toast', () => ({ default: toast }));
vi.mock('framer-motion', async () => {
  const React = await import('react');
  const strip = (tag: string) => {
    const Plain = React.forwardRef<HTMLElement, Record<string, unknown>>(({ children, initial, animate, exit, transition, ...rest }, ref) => {
      void initial; void animate; void exit; void transition;
      return React.createElement(tag, { ...rest, ref }, children as React.ReactNode);
    });
    Plain.displayName = `motion.${tag}`;
    return Plain;
  };
  return { AnimatePresence: ({ children }: { children: React.ReactNode }) => children, motion: { div: strip('div') } };
});

import { ApiError } from '@/lib/api';
import { InboxTokensPanel } from './InboxTokensPanel';

const templates: InboxTemplate[] = [
  { template_id: 'pagerduty', label: 'PagerDuty', description: 'Incidents from PagerDuty', category: 'alerting' },
  { template_id: 'generic_json', label: 'Generic JSON', description: 'Any JSON POST', category: 'generic' },
  { template_id: 'weird', label: 'Weird thing', description: 'Unlisted category', category: 'zzz' },
];

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

function token(over: Partial<InboxTokenListItem> = {}): InboxTokenListItem {
  return {
    fingerprint: 'fp-aaaa',
    template_id: 'pagerduty',
    label: 'on-call',
    has_hmac_secret: true,
    created_at: minutesAgo(120),
    revoked_at: null,
    last_used_at: minutesAgo(5),
    ...over,
  };
}

const secret: InboxTokenSecret = {
  token: 'tok-plain-123',
  inbox_url: 'https://aisoc.example.test/inbox/tok-plain-123',
  template_id: 'pagerduty',
  label: 'on-call',
  has_hmac_secret: true,
  created_at: minutesAgo(0),
  revoked_at: null,
  last_used_at: null,
};

async function openPanel() {
  const user = userEvent.setup();
  render(<InboxTokensPanel />);
  await user.click(screen.getByRole('button', { name: /Universal capture/ }));
  return user;
}

beforeEach(() => {
  vi.clearAllMocks();
  api.templates.mockResolvedValue(templates);
  api.list.mockResolvedValue([token()]);
});

describe('InboxTokensPanel loading', () => {
  it('makes no request until the panel is opened', () => {
    render(<InboxTokensPanel />);
    expect(api.templates).not.toHaveBeenCalled();
    expect(api.list).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: /Universal capture/ })).toHaveAttribute('aria-expanded', 'false');
  });

  it('loads templates and tokens once on first open and lists the token with its template label', async () => {
    await openPanel();
    expect(await screen.findByText('on-call')).toBeInTheDocument();
    expect(api.templates).toHaveBeenCalledTimes(1);
    expect(api.list).toHaveBeenCalledTimes(1);
    const row = screen.getByText('fp-aaaa').closest('tr')!;
    expect(within(row).getByText('PagerDuty')).toBeInTheDocument();
    expect(within(row).getByText('on')).toBeInTheDocument();
  });

  it('shows the count of live tokens while collapsed, ignoring revoked ones', async () => {
    api.list.mockResolvedValue([token(), token({ fingerprint: 'fp-bbbb' }), token({ fingerprint: 'fp-cccc', revoked_at: minutesAgo(1) })]);
    const user = await openPanel();
    await screen.findByText('fp-bbbb');
    await user.click(screen.getByRole('button', { name: /Universal capture/ }));
    expect(screen.getByText(/2 active/)).toBeInTheDocument();
  });

  it('says so when there are no tokens', async () => {
    api.list.mockResolvedValue([]);
    await openPanel();
    expect(await screen.findByText('No inbox URLs yet.')).toBeInTheDocument();
  });

  it('shows the load error with a Retry that tries again', async () => {
    api.templates.mockRejectedValueOnce(new ApiError('Forbidden', 403, ''));
    const user = await openPanel();
    expect(await screen.findByText(/Forbidden/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('fp-aaaa')).toBeInTheDocument();
    expect(api.templates).toHaveBeenCalledTimes(2);
  });

  it('uses a generic message for a non-Error rejection', async () => {
    api.list.mockRejectedValueOnce('nope');
    await openPanel();
    expect(await screen.findByText(/Failed to load inbox tokens/)).toBeInTheDocument();
  });

  it('falls back to the template id and dashes when the template, label or last-use is missing', async () => {
    api.list.mockResolvedValue([token({ template_id: 'gone_template', label: null, last_used_at: null })]);
    await openPanel();
    const row = (await screen.findByText('gone_template')).closest('tr')!;
    expect(within(row).getAllByText('—').length).toBeGreaterThanOrEqual(2);
  });

  it('writes relative times in the right unit', async () => {
    api.list.mockResolvedValue([token({ created_at: minutesAgo(60 * 30), last_used_at: minutesAgo(5) })]);
    await openPanel();
    const row = (await screen.findByText('fp-aaaa')).closest('tr')!;
    expect(within(row).getByText('5m ago')).toBeInTheDocument();
    expect(within(row).getByText('30h ago')).toBeInTheDocument();
  });
});

describe('InboxTokensPanel mint form', () => {
  it('offers templates grouped in the fixed category order, unknown categories last, and preselects the first template of the catalog', async () => {
    await openPanel();
    await screen.findByText('fp-aaaa');
    const groups = Array.from(document.querySelectorAll('optgroup')).map((g) => g.label);
    expect(groups).toEqual(['Generic', 'Alerting', 'zzz']);
    expect(screen.getByRole('combobox')).toHaveValue('pagerduty');
    expect(screen.getByText('Incidents from PagerDuty')).toBeInTheDocument();
  });

  it('refuses a short HMAC secret without calling the API', async () => {
    const user = await openPanel();
    await screen.findByText('fp-aaaa');
    await user.click(screen.getByRole('checkbox'));
    await user.type(screen.getByPlaceholderText(/Shared secret/), 'short');
    await user.click(screen.getByRole('button', { name: 'Mint URL' }));
    expect(toast.error).toHaveBeenCalledWith('HMAC secret must be at least 16 characters');
    expect(api.mint).not.toHaveBeenCalled();
  });

  it('mints with the trimmed label and secret, then shows the one-time URL and refreshes the list', async () => {
    api.mint.mockResolvedValue(secret);
    const user = await openPanel();
    await screen.findByText('fp-aaaa');
    await user.selectOptions(screen.getByRole('combobox'), 'pagerduty');
    await user.type(screen.getByPlaceholderText('PagerDuty on-call'), '  prod  ');
    await user.click(screen.getByRole('checkbox'));
    await user.type(screen.getByPlaceholderText(/Shared secret/), '  0123456789abcdef  ');
    await user.click(screen.getByRole('button', { name: 'Mint URL' }));
    await waitFor(() =>
      expect(api.mint).toHaveBeenCalledWith({ template_id: 'pagerduty', label: 'prod', hmac_secret: '0123456789abcdef' }),
    );
    expect(await screen.findByDisplayValue(secret.inbox_url)).toBeInTheDocument();
    expect(screen.getByDisplayValue('tok-plain-123')).toBeInTheDocument();
    await waitFor(() => expect(api.list).toHaveBeenCalledTimes(2));
    expect(screen.getByPlaceholderText('PagerDuty on-call')).toHaveValue('');
    expect(toast.success).toHaveBeenCalledWith('Minted PagerDuty URL');
  });

  it('does not send a secret that was typed and then switched off', async () => {
    api.mint.mockResolvedValue(secret);
    const user = await openPanel();
    await screen.findByText('fp-aaaa');
    await user.click(screen.getByRole('checkbox'));
    await user.type(screen.getByPlaceholderText(/Shared secret/), '0123456789abcdef');
    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByRole('button', { name: 'Mint URL' }));
    await waitFor(() => expect(api.mint).toHaveBeenCalledWith({ template_id: 'pagerduty', label: null, hmac_secret: null }));
  });

  it('sends null label and secret when neither is given', async () => {
    api.mint.mockResolvedValue({ ...secret, has_hmac_secret: false });
    const user = await openPanel();
    await screen.findByText('fp-aaaa');
    await user.click(screen.getByRole('button', { name: 'Mint URL' }));
    await waitFor(() => expect(api.mint).toHaveBeenCalledWith({ template_id: 'pagerduty', label: null, hmac_secret: null }));
    expect(screen.queryByText(/HMAC verification is enabled/)).not.toBeInTheDocument();
  });

  it('keeps what was typed when minting fails', async () => {
    api.mint.mockRejectedValue(new ApiError('Quota reached', 429, ''));
    const user = await openPanel();
    await screen.findByText('fp-aaaa');
    await user.type(screen.getByPlaceholderText('PagerDuty on-call'), 'keep me');
    await user.click(screen.getByRole('button', { name: 'Mint URL' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Quota reached'));
    expect(screen.getByPlaceholderText('PagerDuty on-call')).toHaveValue('keep me');
    expect(screen.queryByText(/won.t be shown again/)).not.toBeInTheDocument();
  });
});

describe('InboxTokensPanel one-time disclosure', () => {
  it('closes with Done and the secret is gone', async () => {
    api.rotate.mockResolvedValue(secret);
    const user = await openPanel();
    await user.click(await screen.findByRole('button', { name: 'Rotate' }));
    expect(await screen.findByDisplayValue(secret.token)).toBeInTheDocument();
    expect(screen.getByText(/HMAC verification is enabled/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Done' }));
    expect(screen.queryByDisplayValue(secret.token)).not.toBeInTheDocument();
  });

  it('copies the URL and reports a failed copy honestly', async () => {
    api.rotate.mockResolvedValue(secret);
    const user = await openPanel();
    await user.click(await screen.findByRole('button', { name: 'Rotate' }));
    await screen.findByDisplayValue(secret.token);
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    await user.click(screen.getByRole('button', { name: 'Copy URL' }));
    expect(writeText).toHaveBeenCalledWith(secret.inbox_url);
    expect(toast.success).toHaveBeenCalledWith('Copied URL');
    writeText.mockRejectedValue(new Error('denied'));
    await user.click(screen.getByRole('button', { name: 'Copy token' }));
    expect(toast.error).toHaveBeenCalledWith("Couldn't copy token — copy by hand");
  });
});

describe('InboxTokensPanel rotate and revoke', () => {
  it('rotate calls the API with the fingerprint, then refreshes', async () => {
    api.rotate.mockResolvedValue(secret);
    const user = await openPanel();
    await user.click(await screen.findByRole('button', { name: 'Rotate' }));
    await waitFor(() => expect(api.rotate).toHaveBeenCalledWith('fp-aaaa'));
    await waitFor(() => expect(api.list).toHaveBeenCalledTimes(2));
  });

  it('a failed rotate shows the error and discloses nothing', async () => {
    api.rotate.mockRejectedValue(new ApiError('Token already revoked', 409, ''));
    const user = await openPanel();
    await user.click(await screen.findByRole('button', { name: 'Rotate' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Token already revoked'));
    expect(screen.queryByText(/won.t be shown again/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Rotate' })).toBeEnabled();
  });

  it('revoke does nothing unless the operator confirms', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    const user = await openPanel();
    await user.click(await screen.findByRole('button', { name: 'Revoke' }));
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(api.revoke).not.toHaveBeenCalled();
    expect(api.list).toHaveBeenCalledTimes(1);
    confirm.mockRestore();
  });

  it('a confirmed revoke calls the API and refreshes', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    api.revoke.mockResolvedValue(undefined);
    const user = await openPanel();
    await user.click(await screen.findByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(api.revoke).toHaveBeenCalledWith('fp-aaaa'));
    expect(toast.success).toHaveBeenCalledWith('Token revoked');
    await waitFor(() => expect(api.list).toHaveBeenCalledTimes(2));
    confirm.mockRestore();
  });

  it('disables only the row being worked on while its request is in flight', async () => {
    api.list.mockResolvedValue([token(), token({ fingerprint: 'fp-bbbb' })]);
    let finish: (s: InboxTokenSecret) => void = () => {};
    api.rotate.mockReturnValue(new Promise<InboxTokenSecret>((r) => (finish = r)));
    const user = await openPanel();
    const rotates = await screen.findAllByRole('button', { name: 'Rotate' });
    await user.click(rotates[0]);
    await waitFor(() => expect(screen.getAllByRole('button', { name: 'Rotate' })[0]).toBeDisabled());
    expect(screen.getAllByRole('button', { name: 'Rotate' })[1]).toBeEnabled();
    expect(screen.getAllByRole('button', { name: 'Revoke' })[0]).toBeDisabled();
    finish(secret);
    await waitFor(() => expect(screen.getAllByRole('button', { name: 'Rotate' })[0]).toBeEnabled());
  });
});
