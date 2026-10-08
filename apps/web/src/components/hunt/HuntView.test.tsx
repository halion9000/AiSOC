import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

// Monaco needs a real browser; a textarea stands in for the editor.
vi.mock('next/dynamic', () => ({
  __esModule: true,
  default: () =>
    function Editor(props: { value?: string; onChange?: (v?: string) => void }) {
      return <textarea data-testid="editor" value={props.value ?? ''} onChange={(e) => props.onChange?.(e.target.value)} />;
    },
}));

const toastError = vi.hoisted(() => vi.fn());
const toastFn = vi.hoisted(() => vi.fn());
vi.mock('react-hot-toast', () => ({ __esModule: true, default: Object.assign(toastFn, { error: toastError, success: vi.fn() }) }));

const search = vi.hoisted(() => vi.fn());
const listSaved = vi.hoisted(() => vi.fn());
const translate = vi.hoisted(() => vi.fn());
const savedHunts = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({
  __esModule: true,
  huntApi: { search: (q: unknown) => search(q), listSaved: () => listSaved(), saveSearch: vi.fn(), deleteSaved: vi.fn() },
  nlQueryApi: { translate: (q: unknown) => translate(q) },
  savedHuntsApi: { list: () => savedHunts(), create: vi.fn(), remove: vi.fn(), delete: vi.fn(), touch: vi.fn() },
}));

import { HuntView } from './HuntView';

// On a failed search this page put invented hits in the results ("john.doe" on "WORKSTATION-042", from a hard-coded list), flipped a "demo" flag, and toasted
// "showing demo results"; on a failed first load it substituted three invented saved searches; and if a natural-language question could not be translated it
// announced "using demo results" and ran whatever query was already in the editor. A failure now shows as a failure.
const INVENTED_HITS = ['john.doe', 'WORKSTATION-042'];
const INVENTED_SAVED = ['Encoded PowerShell', 'LSASS access attempts', 'Outbound connections to TOR exits'];

const realHits = {
  total: 2,
  took: 17,
  hits: [
    { id: 'h1', timestamp: '2026-10-08T01:00:00Z', source: 'edr', severity: 'high', fields: { host: 'real-host-1', user: 'alice' } },
    { id: 'h2', timestamp: '2026-10-08T01:01:00Z', source: 'edr', severity: 'low', fields: { host: 'real-host-2', user: 'bob' } },
  ],
};

function renderHunt() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <HuntView />
    </SWRConfig>,
  );
}

const runButton = () => screen.getByRole('button', { name: /run hunt/i });

beforeEach(() => {
  [search, listSaved, translate, savedHunts, toastError, toastFn].forEach((m) => m.mockReset());
  listSaved.mockResolvedValue({ searches: [] });
  savedHunts.mockResolvedValue([]);
});

describe('a failed search', () => {
  it('shows the error with a Retry, and none of the invented results', async () => {
    search.mockRejectedValue(new Error('503 search backend down'));
    const { container } = renderHunt();
    await userEvent.setup().click(runButton());

    expect(await screen.findByText('Search failed')).toBeInTheDocument();
    expect(screen.getByText(/503 search backend down/)).toBeInTheDocument();
    for (const invented of INVENTED_HITS) expect(container.textContent).not.toContain(invented);
    expect(container.textContent).not.toMatch(/demo/i);
    expect(toastError).toHaveBeenCalledWith('Search failed: 503 search backend down');
    expect(toastFn).not.toHaveBeenCalled(); // not the old "showing demo results" toast
  });

  it('retries, and then shows the real results', async () => {
    search.mockRejectedValueOnce(new Error('boom')).mockResolvedValue(realHits);
    renderHunt();
    const user = userEvent.setup();
    await user.click(runButton());
    await user.click(await screen.findByRole('button', { name: /retry|try again/i }));
    expect(await screen.findByText('real-host-1', { exact: false })).toBeInTheDocument();
    expect(screen.queryByText('Search failed')).not.toBeInTheDocument();
  });

  it('is not shown as "no matches": an error is not an empty result', async () => {
    search.mockRejectedValue(new Error('boom'));
    renderHunt();
    await userEvent.setup().click(runButton());
    await screen.findByText('Search failed');
    expect(screen.queryByText('No matches in the selected window')).not.toBeInTheDocument();
  });
});

describe('a search that works', () => {
  it('shows the real hits and the real count', async () => {
    search.mockResolvedValue(realHits);
    const { container } = renderHunt();
    await userEvent.setup().click(runButton());
    expect(await screen.findByText('real-host-1', { exact: false })).toBeInTheDocument();
    expect(screen.getByText('real-host-2', { exact: false })).toBeInTheDocument();
    expect(screen.getByText(/2 hits/)).toBeInTheDocument();
    for (const invented of INVENTED_HITS) expect(container.textContent).not.toContain(invented);
  });

  it('says there were no matches, without blaming the backend, when there were none', async () => {
    search.mockResolvedValue({ total: 0, took: 5, hits: [] });
    renderHunt();
    await userEvent.setup().click(runButton());
    expect(await screen.findByText('No matches in the selected window')).toBeInTheDocument();
    expect(screen.queryByText(/backend unreachable/i)).not.toBeInTheDocument();
    expect(screen.getByText('Either the data is clean, or the query is too tight.')).toBeInTheDocument();
  });
});

describe('saved searches', () => {
  it('shows an error, and none of the three invented saved searches, when the load fails', async () => {
    listSaved.mockRejectedValue(new Error('saved searches unavailable'));
    const { container } = renderHunt();
    await waitFor(() => expect(listSaved).toHaveBeenCalled());
    await waitFor(() => expect(container.textContent).toMatch(/saved searches unavailable|couldn't|could not|failed/i));
    for (const invented of INVENTED_SAVED) expect(container.textContent).not.toContain(invented);
    expect(container.textContent).not.toMatch(/demo/i);
  });

  it('lists the real ones', async () => {
    listSaved.mockResolvedValue({ searches: [{ id: 's1', name: 'My real saved search', query: 'host.name: x', language: 'kql', createdAt: '2026-10-01T00:00:00Z' }] });
    const { container } = renderHunt();
    expect(await screen.findByText('My real saved search')).toBeInTheDocument();
    for (const invented of INVENTED_SAVED) expect(container.textContent).not.toContain(invented);
  });
});

describe('the status pill', () => {
  async function askAQuestion() {
    translate.mockResolvedValue({ esql: 'FROM events | LIMIT 5', explanation: 'x' });
    search.mockResolvedValue(realHits);
    renderHunt();
    const user = userEvent.setup();
    await user.type(screen.getByPlaceholderText(/Show me suspicious sudo/), 'show me things{enter}');
    await screen.findByText('real-host-1', { exact: false });
    return user;
  }

  it('says "Live backend" while things work', async () => {
    await askAQuestion();
    expect(screen.getByText('Live backend')).toBeInTheDocument();
    expect(screen.queryByText(/demo data/i)).not.toBeInTheDocument();
  });

  it('says "Backend unreachable" after a failure, and never "Demo data"', async () => {
    const user = await askAQuestion();
    search.mockRejectedValue(new Error('boom'));
    await user.click(runButton());
    expect(await screen.findByText('Backend unreachable')).toBeInTheDocument();
    expect(screen.queryByText(/demo data/i)).not.toBeInTheDocument();
  });
});

describe('asking a question in plain language', () => {
  const type = async (text: string) => {
    renderHunt();
    const user = userEvent.setup();
    await user.type(screen.getByPlaceholderText(/Show me suspicious sudo/), `${text}{enter}`);
    return user;
  };

  it('translates, puts the query in the editor, and runs it', async () => {
    translate.mockResolvedValue({ esql: 'FROM auth | WHERE user == "alice"', explanation: 'alice logins' });
    search.mockResolvedValue(realHits);
    await type('alice logins');
    await waitFor(() => expect(search).toHaveBeenCalledTimes(1));
    expect(search.mock.calls[0][0]).toMatchObject({ query: 'FROM auth | WHERE user == "alice"', language: 'esql' });
    expect((screen.getByTestId('editor') as HTMLTextAreaElement).value).toBe('FROM auth | WHERE user == "alice"');
  });

  it('STOPS when the question cannot be translated: it runs nothing, and says why', async () => {
    translate.mockRejectedValue(new Error('translator offline'));
    const { container } = { container: document.body };
    await type('anything');
    await waitFor(() => expect(toastError).toHaveBeenCalled());
    expect(toastError.mock.calls[0][0]).toContain('Could not translate the question: translator offline');
    expect(search).not.toHaveBeenCalled(); // it used to run whatever was already in the editor
    expect(container.textContent).not.toMatch(/demo/i);
    for (const invented of INVENTED_HITS) expect(container.textContent).not.toContain(invented);
  });

  it('treats a translation with no query in it as a failure, not as a reason to run something else', async () => {
    translate.mockResolvedValue({ esql: '   ', explanation: '' });
    await type('anything');
    await waitFor(() => expect(toastError).toHaveBeenCalled());
    expect(toastError.mock.calls[0][0]).toContain('the translator returned no query');
    expect(search).not.toHaveBeenCalled();
  });
});
