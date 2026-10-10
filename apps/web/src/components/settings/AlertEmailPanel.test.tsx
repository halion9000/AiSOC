import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';
import { SWRConfig } from 'swr';

const alertEmailApi = vi.hoisted(() => ({ get: vi.fn(), update: vi.fn(), test: vi.fn(), log: vi.fn() }));
vi.mock('@/lib/api', async (original) => ({ ...(await original<typeof import('@/lib/api')>()), alertEmailApi }));
const tenantState = vi.hoisted(() => vi.fn());
vi.mock('@/components/layout/TenantProvider', () => ({ useTenant: () => tenantState() }));
const toastSuccess = vi.hoisted(() => vi.fn());
vi.mock('react-hot-toast', () => ({ __esModule: true, default: { success: toastSuccess, error: vi.fn() } }));
vi.mock('date-fns', async () => ({ ...(await vi.importActual<typeof import('date-fns')>('date-fns')), formatDistanceToNow: () => '3 minutes ago' }));

import { ApiError } from '@/lib/api';
import { AlertEmailPanel, parseRecipients } from './AlertEmailPanel';

const status = (over: Record<string, unknown> = {}) => ({
  enabled: false, min_severity: 'high', recipients: [], enabled_since: null, updated_by: null, updated_at: null, last_sent_at: null, last_error: null, last_error_at: null, consecutive_failures: 0,
  worker_enabled: true, credentials_configured: true, missing_credentials: [], sender: 'alerts@msp.example', warnings: [], ...over,
});
const sent = (over: Record<string, unknown> = {}) => ({ alert_id: 'a1', tenant_id: 't1', tenant_name: 'Acme Corp', severity: 'critical', title: 'Impossible travel for jdoe', sent_at: '2026-10-10T12:00:00Z', batch_id: 'b1', recipient_count: 2, ...over });
const refusal = (status: number, detail: unknown) => new ApiError(`API ${status} - /x`, status, JSON.stringify({ detail }));

beforeEach(() => {
  Object.values(alertEmailApi).forEach((f) => f.mockReset());
  toastSuccess.mockReset();
  tenantState.mockReturnValue({ viewingOther: false, home: { name: 'Live Oak IT' } });
  alertEmailApi.get.mockResolvedValue(status());
  alertEmailApi.log.mockResolvedValue([]);
  alertEmailApi.update.mockImplementation(async (body: Record<string, unknown>) => status({ ...body }));
  alertEmailApi.test.mockResolvedValue({ sent_to: ['ops@msp.example'] });
});

function renderPanel() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <AlertEmailPanel />
    </SWRConfig>,
  );
}

describe('parseRecipients', () => {
  it.each([
    ['ops@a.example', ['ops@a.example']],
    ['ops@a.example\nlead@a.example', ['ops@a.example', 'lead@a.example']],
    ['ops@a.example, lead@a.example; third@a.example', ['ops@a.example', 'lead@a.example', 'third@a.example']],
    ['  ops@a.example  \n\n  \n lead@a.example ,, ', ['ops@a.example', 'lead@a.example']],
    ['', []],
    ['   \n  ', []],
  ])('%j', (text, expected) => expect(parseRecipients(text)).toEqual(expected));
});

describe('AlertEmailPanel', () => {
  it('while viewing another tenant it offers nothing and asks for no data', async () => {
    tenantState.mockReturnValue({ viewingOther: true, home: { name: 'Live Oak IT' } });
    renderPanel();
    expect(await screen.findByTestId('viewing-other-notice')).toHaveTextContent('Return to Live Oak IT');
    expect(alertEmailApi.get).not.toHaveBeenCalled();
  });

  it("shows a failure to load in the API's own words", async () => {
    alertEmailApi.get.mockRejectedValue(refusal(403, 'Platform administrators only'));
    renderPanel();
    expect(await screen.findByRole('alert')).toHaveTextContent('Platform administrators only');
  });

  it('shows the saved state: off, the sender, and that nothing has been sent', async () => {
    renderPanel();
    expect(await screen.findByTestId('alert-email-state')).toHaveTextContent('Off');
    expect(screen.getByTestId('alert-email-status')).toHaveTextContent('alerts@msp.example');
    expect(screen.getByTestId('alert-email-status')).toHaveTextContent('Nothing sent yet');
  });

  it('shows it on, with when the last message went out', async () => {
    alertEmailApi.get.mockResolvedValue(status({ enabled: true, recipients: ['ops@msp.example'], last_sent_at: '2026-10-10T12:00:00Z' }));
    renderPanel();
    expect(await screen.findByTestId('alert-email-state')).toHaveTextContent('On');
    expect(screen.getByTestId('alert-email-status')).toHaveTextContent('Last sent 3 minutes ago');
  });

  it('shows the server\'s warnings and the variables that are not set, by name only', async () => {
    alertEmailApi.get.mockResolvedValue(status({ enabled: true, recipients: ['ops@msp.example'], credentials_configured: false, missing_credentials: ['ALERT_EMAIL_GRAPH_CLIENT_SECRET', 'ALERT_EMAIL_SENDER'], sender: null, warnings: ['Alert email is on, but the background worker is switched off in this deployment (ALERT_EMAIL_WORKER_ENABLED), so nothing will be sent.'] }));
    renderPanel();
    expect(await screen.findByTestId('alert-email-warning')).toHaveTextContent('ALERT_EMAIL_WORKER_ENABLED');
    expect(screen.getByTestId('alert-email-missing')).toHaveTextContent('ALERT_EMAIL_GRAPH_CLIENT_SECRET, ALERT_EMAIL_SENDER');
    expect(screen.getByTestId('alert-email-status')).toHaveTextContent('not set');
  });

  it('shows no missing-variables line when everything is set', async () => {
    renderPanel();
    await screen.findByTestId('alert-email-state');
    expect(screen.queryByTestId('alert-email-missing')).toBeNull();
    expect(screen.queryByTestId('alert-email-last-error')).toBeNull();
  });

  it('shows the last error with how often it has failed, and says unsent alerts wait', async () => {
    alertEmailApi.get.mockResolvedValue(status({ last_error: 'Microsoft Graph refused the message: HTTP 403 ErrorAccessDenied', last_error_at: '2026-10-10T12:00:00Z', consecutive_failures: 3 }));
    renderPanel();
    const box = await screen.findByTestId('alert-email-last-error');
    expect(box).toHaveTextContent('HTTP 403 ErrorAccessDenied');
    expect(box).toHaveTextContent('3 minutes ago');
    expect(box).toHaveTextContent('failed 3 times in a row');
    expect(box).toHaveTextContent('Unsent alerts stay waiting');
  });

  it('does not claim repeated failure after a single one', async () => {
    alertEmailApi.get.mockResolvedValue(status({ last_error: 'HTTP 503', consecutive_failures: 1 }));
    renderPanel();
    expect(await screen.findByTestId('alert-email-last-error')).not.toHaveTextContent('in a row');
  });

  it('puts the saved recipients one per line in the form', async () => {
    alertEmailApi.get.mockResolvedValue(status({ recipients: ['ops@msp.example', 'lead@msp.example'], min_severity: 'critical', enabled: true }));
    renderPanel();
    expect(await screen.findByLabelText('Recipients')).toHaveValue('ops@msp.example\nlead@msp.example');
    expect(screen.getByLabelText('Minimum severity')).toHaveValue('critical');
    expect(screen.getByLabelText('Send alert emails')).toBeChecked();
  });

  it('changing the recipients asks first, listing who will receive other tenants\' alert titles; cancelling saves nothing', async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.type(await screen.findByLabelText('Recipients'), 'ops@msp.example, lead@msp.example');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog).toHaveTextContent("Alert titles from every tenant");
    expect(dialog).toHaveTextContent('ops@msp.example, lead@msp.example');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(alertEmailApi.update).not.toHaveBeenCalled();
  });

  it('confirming saves the parsed list with the severity and the switch, and the form then shows what the server stored', async () => {
    alertEmailApi.update.mockResolvedValue(status({ enabled: true, recipients: ['ops@msp.example', 'lead@msp.example'], min_severity: 'medium' }));
    const user = userEvent.setup();
    renderPanel();
    await user.type(await screen.findByLabelText('Recipients'), 'Ops@MSP.example; lead@msp.example');
    await user.selectOptions(screen.getByLabelText('Minimum severity'), 'medium');
    await user.click(screen.getByLabelText('Send alert emails'));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(alertEmailApi.update).toHaveBeenCalledWith({ recipients: ['Ops@MSP.example', 'lead@msp.example'], min_severity: 'medium', enabled: true }));
    await waitFor(() => expect(screen.getByLabelText('Recipients')).toHaveValue('ops@msp.example\nlead@msp.example'));
    expect(screen.getByTestId('alert-email-state')).toHaveTextContent('On');
    expect(toastSuccess).toHaveBeenCalledWith('Alert email settings saved');
  });

  it('switching it on asks first even when the recipients are unchanged', async () => {
    alertEmailApi.get.mockResolvedValue(status({ recipients: ['ops@msp.example'] }));
    const user = userEvent.setup();
    renderPanel();
    await user.click(await screen.findByLabelText('Send alert emails'));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByRole('alertdialog')).toBeInTheDocument();
    expect(alertEmailApi.update).not.toHaveBeenCalled();
  });

  it('changing only the severity, or switching it off, saves at once with no prompt', async () => {
    alertEmailApi.get.mockResolvedValue(status({ enabled: true, recipients: ['ops@msp.example'] }));
    const user = userEvent.setup();
    renderPanel();
    await user.selectOptions(await screen.findByLabelText('Minimum severity'), 'low');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(alertEmailApi.update).toHaveBeenCalledWith({ recipients: ['ops@msp.example'], min_severity: 'low', enabled: true }));
    expect(screen.queryByRole('alertdialog')).toBeNull();
    alertEmailApi.update.mockClear();
    await user.click(screen.getByLabelText('Send alert emails'));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(alertEmailApi.update).toHaveBeenCalledWith({ recipients: ['ops@msp.example'], min_severity: 'low', enabled: false }));
    expect(screen.queryByRole('alertdialog')).toBeNull();
  });

  it("shows the server's reason when a save is refused, and keeps what was typed", async () => {
    alertEmailApi.update.mockRejectedValue(refusal(422, 'not a plain email address: \'Ops <ops@x>\''));
    const user = userEvent.setup();
    renderPanel();
    await user.type(await screen.findByLabelText('Recipients'), 'Ops <ops@x>');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Save' }));
    expect(await screen.findByTestId('alert-email-error')).toHaveTextContent('not a plain email address');
    expect(screen.getByLabelText('Recipients')).toHaveValue('Ops <ops@x>');
  });

  it('shows a list of validation problems from the server as one sentence', async () => {
    alertEmailApi.update.mockRejectedValue(refusal(422, [{ msg: 'Input should be a valid list' }, { msg: 'Field required' }]));
    const user = userEvent.setup();
    renderPanel();
    await user.selectOptions(await screen.findByLabelText('Minimum severity'), 'low');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByTestId('alert-email-error')).toHaveTextContent('Input should be a valid list; Field required');
  });

  it('sends a test email and says to whom', async () => {
    alertEmailApi.test.mockResolvedValue({ sent_to: ['ops@msp.example', 'lead@msp.example'] });
    const user = userEvent.setup();
    renderPanel();
    await user.click(await screen.findByRole('button', { name: 'Send a test email' }));
    const result = await screen.findByTestId('alert-email-test-result');
    expect(result).toHaveTextContent('Sent a test message to ops@msp.example, lead@msp.example.');
    expect(result).toHaveAttribute('data-ok', 'true');
  });

  it("shows the server's reason when the test fails (no recipient, not configured, rate-limited, Microsoft refused)", async () => {
    const user = userEvent.setup();
    renderPanel();
    for (const detail of ['Add at least one recipient first.', 'These environment variables are not set: ALERT_EMAIL_SENDER.', 'A test email was just sent; wait a few seconds.', 'Microsoft Graph refused the message: HTTP 403 ErrorAccessDenied']) {
      alertEmailApi.test.mockRejectedValueOnce(refusal(409, detail));
      await user.click(await screen.findByRole('button', { name: 'Send a test email' }));
      const result = await screen.findByTestId('alert-email-test-result');
      await waitFor(() => expect(result).toHaveTextContent(detail));
      expect(result).toHaveAttribute('data-ok', 'false');
    }
  });

  it('disables the test button while it is sending, and refreshes the status afterwards', async () => {
    let finish!: (v: { sent_to: string[] }) => void;
    alertEmailApi.test.mockReturnValue(new Promise((res) => { finish = res; }));
    const user = userEvent.setup();
    renderPanel();
    await user.click(await screen.findByRole('button', { name: 'Send a test email' }));
    expect(screen.getByRole('button', { name: 'Sending…' })).toBeDisabled();
    const before = alertEmailApi.get.mock.calls.length;
    finish({ sent_to: ['ops@msp.example'] });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Send a test email' })).toBeEnabled());
    await waitFor(() => expect(alertEmailApi.get.mock.calls.length).toBeGreaterThan(before));
  });

  it('lists recently emailed alerts with their tenant', async () => {
    alertEmailApi.log.mockResolvedValue([sent(), sent({ alert_id: 'a2', tenant_name: null, severity: 'high', title: 'Malware beaconing' })]);
    renderPanel();
    const rows = await screen.findAllByTestId('alert-email-log-row');
    expect(rows[0]).toHaveTextContent('Acme Corp');
    expect(rows[0]).toHaveTextContent('Impossible travel for jdoe');
    expect(rows[1]).toHaveTextContent('unknown tenant');
  });

  it('says so when nothing has been emailed', async () => {
    renderPanel();
    expect(await screen.findByText('Nothing emailed yet')).toBeInTheDocument();
  });

  it('has no accessibility violations', async () => {
    alertEmailApi.get.mockResolvedValue(status({ enabled: true, recipients: ['ops@msp.example'], last_error: 'HTTP 403', consecutive_failures: 2, warnings: ['w'] }));
    alertEmailApi.log.mockResolvedValue([sent()]);
    const { container } = renderPanel();
    await screen.findByTestId('alert-email-last-error');
    expect(await axe(container, { rules: { 'color-contrast': { enabled: false } } })).toHaveNoViolations();
  });
});
