import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

vi.mock('next/dynamic', () => ({
  __esModule: true,
  default: () =>
    function Editor(props: { value?: string; onChange?: (v?: string) => void }) {
      return <textarea data-testid="editor" value={props.value ?? ''} onChange={(e) => props.onChange?.(e.target.value)} />;
    },
}));
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn() }) }));
vi.mock('@/components/copilot/ContextualActions', () => ({ ContextualActions: () => null }));

const api = vi.hoisted(() => ({ test: vi.fn(), get: vi.fn(), create: vi.fn(), update: vi.fn(), delete: vi.fn(), backtest: vi.fn() }));
const toastFn = vi.hoisted(() => vi.fn());
const toastError = vi.hoisted(() => vi.fn());
const toastSuccess = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ __esModule: true, detectionApi: api }));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: Object.assign(toastFn, { error: toastError, success: toastSuccess }) }));

import { RuleEditor } from './RuleEditor';

// When the detection backend could not run a rule test, this editor fell back to evaluateDemo(): a client-side imitation of the detection engine with its own
// light heuristics. It put its verdict in the results panel and toasted "Demo evaluator: matched N event(s) (offline mode)" or "Demo evaluator: no match". So a
// detection engineer could be told a rule matched (or did not) by something that never ran the rule, and then ship it. A test that cannot run now says so.
const hit = { id: 'e1', timestamp: '2026-10-08T01:00:00Z', source: 'edr', severity: 'high', fields: { host: 'real-host-1' } };

function renderEditor() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <RuleEditor mode="create" />
    </SWRConfig>,
  );
}
const runTest = () => screen.getByRole('button', { name: 'Run test' });

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  [toastFn, toastError, toastSuccess].forEach((m) => m.mockReset());
});

describe('Run test, when the detection service cannot run it', () => {
  it('says the test could not run, and gives no verdict', async () => {
    api.test.mockRejectedValue(new Error('503 detection engine down'));
    const { container } = renderEditor();
    await userEvent.setup().click(runTest());

    expect(await screen.findByText(/The test could not run: 503 detection engine down/)).toBeInTheDocument();
    expect(toastError).toHaveBeenCalledWith('Rule test failed: 503 detection engine down');
    expect(toastFn).not.toHaveBeenCalled(); // not "Demo evaluator: no match (offline mode)"
    expect(toastSuccess).not.toHaveBeenCalled(); // not "Demo evaluator: matched N event(s)"
    expect(container.textContent).not.toMatch(/demo|offline mode|matched \d+ event/i);
    expect(container.textContent).not.toMatch(/Matched\s*\d/);
    expect(screen.queryByText(/Click .*Run test.* to evaluate the rule/)).not.toBeInTheDocument(); // not shown as "nothing run yet" either
  });

  it('says so plainly even when the failure carries no message', async () => {
    api.test.mockRejectedValue('nope');
    renderEditor();
    await userEvent.setup().click(runTest());
    expect(await screen.findByText(/The test could not run: the detection service is unreachable/)).toBeInTheDocument();
    expect(toastError).toHaveBeenCalledWith('Rule test failed: the detection service is unreachable');
  });

  it('clears an earlier result, so a stale "Matched" is never shown next to a failure', async () => {
    api.test.mockResolvedValueOnce({ matches: 1, preview: [hit] }).mockRejectedValue(new Error('boom'));
    renderEditor();
    const user = userEvent.setup();
    await user.click(runTest());
    expect(await screen.findByText(/Matched\s*1\s*event/)).toBeInTheDocument();
    await user.click(runTest());
    expect(await screen.findByText(/The test could not run: boom/)).toBeInTheDocument();
    expect(screen.queryByText(/Matched\s*1\s*event/)).not.toBeInTheDocument();
  });

  it('clears the error on the next run that works', async () => {
    api.test.mockRejectedValueOnce(new Error('boom')).mockResolvedValue({ matches: 1, preview: [hit] });
    renderEditor();
    const user = userEvent.setup();
    await user.click(runTest());
    await screen.findByText(/The test could not run: boom/);
    await user.click(runTest());
    expect(await screen.findByText(/Matched\s*1\s*event/)).toBeInTheDocument();
    expect(screen.queryByText(/The test could not run/)).not.toBeInTheDocument();
  });
});

describe('Run test, when the detection service runs it', () => {
  it('shows the engine\'s own verdict for a match, and sends the language, rule body and sample event', async () => {
    api.test.mockResolvedValue({ matches: 2, preview: [hit] });
    renderEditor();
    await userEvent.setup().click(runTest());
    expect(await screen.findByText(/Matched\s*2\s*events/)).toBeInTheDocument();
    expect(toastSuccess).toHaveBeenCalledWith(expect.stringContaining('2 event(s)'));
    expect(api.test).toHaveBeenCalledTimes(1);
    expect(api.test.mock.calls[0][0]).toMatchObject({ language: 'sigma' });
    expect(typeof api.test.mock.calls[0][0].body).toBe('string');
    expect(typeof api.test.mock.calls[0][0].sample).toBe('string');
  });

  it('reports no match without calling it a demo', async () => {
    api.test.mockResolvedValue({ matches: 0, preview: [] });
    const { container } = renderEditor();
    await userEvent.setup().click(runTest());
    await waitFor(() => expect(toastFn).toHaveBeenCalledWith('No match against the sample'));
    expect(container.textContent).not.toMatch(/demo|offline/i);
    expect(toastError).not.toHaveBeenCalled();
  });
});
