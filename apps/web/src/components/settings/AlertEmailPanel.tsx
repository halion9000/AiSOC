'use client';

import { useState } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import { formatDistanceToNow } from 'date-fns';

import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { Skeleton } from '@/components/ui/Skeleton';
import { useTenant } from '@/components/layout/TenantProvider';
import { alertEmailApi, type AlertSeverity, type AlertEmailUpdate } from '@/lib/api';
import { Field, PanelHeader, errorText, inputClass } from './panel-parts';

const SEVERITIES: AlertSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** One address per line (commas and semicolons also separate), trimmed, empty entries dropped. The server validates and normalises; this only splits. */
export function parseRecipients(text: string): string[] {
  return text
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Emailing new alerts to PLATFORM administrators (server: platform_alert_email.py). It is the way to choose who receives OTHER TENANTS' alert titles, so only a
 * platform administrator sees it, and a save that turns it on or changes the recipients asks first. The Microsoft credentials are environment variables on the
 * server: this screen shows which are missing (by name), never a value.
 */
export function AlertEmailPanel() {
  const { viewingOther, home } = useTenant();
  if (viewingOther) {
    return (
      <div>
        <PanelHeader title="Alert email" description="Email new alerts to platform administrators." />
        <p data-testid="viewing-other-notice" className="px-6 py-5 text-sm text-amber-200">
          This is a platform setting. Return to {home?.name ?? 'your tenant'} (the banner above has the button) and open this page again.
        </p>
      </div>
    );
  }
  return <Inner />;
}

function Inner() {
  const { data: status, isLoading, error: loadError, mutate } = useSWR('settings:alert-email', () => alertEmailApi.get());
  const { data: log, mutate: reloadLog } = useSWR('settings:alert-email-log', () => alertEmailApi.log(20));
  // The form shows the saved values until the person edits a field.
  const [draftRecipients, setDraftRecipients] = useState<string | null>(null);
  const [draftSeverity, setDraftSeverity] = useState<AlertSeverity | null>(null);
  const [draftEnabled, setDraftEnabled] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [confirm, setConfirm] = useState<AlertEmailUpdate | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  if (isLoading && !status) {
    return (
      <div>
        <PanelHeader title="Alert email" description="Email new alerts to platform administrators." />
        <div className="px-6 py-5"><Skeleton className="h-24 w-full rounded-lg" /></div>
      </div>
    );
  }
  if (loadError || !status) {
    return (
      <div>
        <PanelHeader title="Alert email" description="Email new alerts to platform administrators." />
        <p role="alert" className="px-6 py-5 text-sm text-red-300">{errorText(loadError, 'The alert email setting could not be loaded.')}</p>
      </div>
    );
  }

  const recipientsText = draftRecipients ?? status.recipients.join('\n');
  const severity = draftSeverity ?? status.min_severity;
  const enabled = draftEnabled ?? status.enabled;

  const buildUpdate = (): AlertEmailUpdate => ({ recipients: parseRecipients(recipientsText), min_severity: severity, enabled });
  /** Anything that turns it on, or changes who receives the emails, asks first (other tenants' alert titles go to those addresses). */
  const needsAsking = (u: AlertEmailUpdate) => (u.enabled === true && !status.enabled) || JSON.stringify(u.recipients) !== JSON.stringify(status.recipients);

  const save = async (update: AlertEmailUpdate) => {
    setSaving(true);
    try {
      const next = await alertEmailApi.update(update);
      await mutate(next, { revalidate: false });
      setDraftRecipients(null);
      setDraftSeverity(null);
      setDraftEnabled(null);
      setError(null);
      toast.success('Alert email settings saved');
    } catch (err) {
      setError(errorText(err, 'The settings could not be saved.'));
    } finally {
      setSaving(false);
      setConfirm(null);
    }
  };

  const submit = () => {
    const update = buildUpdate();
    setError(null);
    if (needsAsking(update)) setConfirm(update);
    else void save(update);
  };

  const sendTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const out = await alertEmailApi.test();
      setTestResult({ ok: true, text: `Sent a test message to ${out.sent_to.join(', ')}.` });
    } catch (err) {
      setTestResult({ ok: false, text: errorText(err, 'The test message could not be sent.') });
    } finally {
      setTesting(false);
      void mutate();
      void reloadLog();
    }
  };

  return (
    <div>
      <PanelHeader
        title="Alert email"
        description="Email new alerts to platform administrators. The emails carry other tenants' alert titles, so only people you list here receive them."
      />
      <div className="space-y-6 px-6 py-5">
        <section aria-label="Status" data-testid="alert-email-status" className="space-y-3 rounded-lg border border-gray-800 bg-gray-950/40 p-4">
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span data-testid="alert-email-state" className={status.enabled ? 'rounded bg-green-500/15 px-2 py-0.5 text-xs font-medium text-green-200 ring-1 ring-green-500/40' : 'rounded bg-gray-800 px-2 py-0.5 text-xs font-medium text-gray-300 ring-1 ring-gray-700'}>
              {status.enabled ? 'On' : 'Off'}
            </span>
            <span className="text-gray-400">
              Sender: <span className="text-gray-200">{status.sender ?? 'not set'}</span>
            </span>
            {status.last_sent_at ? <span className="text-gray-400" suppressHydrationWarning>Last sent {formatDistanceToNow(new Date(status.last_sent_at), { addSuffix: true })}</span> : <span className="text-gray-500">Nothing sent yet</span>}
          </div>
          {status.warnings.map((w) => (
            <p key={w} data-testid="alert-email-warning" className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-100">{w}</p>
          ))}
          {!status.credentials_configured ? (
            <p data-testid="alert-email-missing" className="text-sm text-gray-300">
              Not set on the server: <span className="font-mono text-xs">{status.missing_credentials.join(', ')}</span>
            </p>
          ) : null}
          {status.last_error ? (
            <p data-testid="alert-email-last-error" role="alert" className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-100">
              Last error{status.last_error_at ? ` (${formatDistanceToNow(new Date(status.last_error_at), { addSuffix: true })})` : ''}: {status.last_error}
              {status.consecutive_failures > 1 ? ` — failed ${status.consecutive_failures} times in a row. Unsent alerts stay waiting and go out once it is fixed.` : ''}
            </p>
          ) : null}
        </section>

        <section aria-label="Settings" className="space-y-4">
          <Field label="Recipients" hint="One email address per line. These people receive alert titles from every tenant.">
            <textarea aria-label="Recipients" rows={4} className={inputClass()} value={recipientsText} onChange={(e) => setDraftRecipients(e.target.value)} placeholder="ops@yourmsp.example" />
          </Field>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
            <Field label="Send alerts at or above">
              <select aria-label="Minimum severity" className={inputClass()} value={severity} onChange={(e) => setDraftSeverity(e.target.value as AlertSeverity)}>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </Field>
            <label className="flex items-center gap-2 pb-2 text-sm text-gray-200">
              <input type="checkbox" aria-label="Send alert emails" checked={enabled} onChange={(e) => setDraftEnabled(e.target.checked)} />
              Send alert emails
            </label>
          </div>
          {error ? <p role="alert" data-testid="alert-email-error" className="text-sm text-red-300">{error}</p> : null}
          <div className="flex flex-wrap gap-3">
            <button type="button" onClick={submit} disabled={saving} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50">
              {saving ? 'Saving…' : 'Save'}
            </button>
            <button type="button" onClick={() => void sendTest()} disabled={testing} className="rounded-lg border border-gray-700 bg-gray-900 px-4 py-2 text-sm text-gray-200 hover:bg-gray-800 disabled:opacity-50">
              {testing ? 'Sending…' : 'Send a test email'}
            </button>
          </div>
          <p className="text-xs text-gray-500">Switching it on only ever sends alerts created after that moment, never a backlog. The test email goes to the saved recipients.</p>
          {testResult ? (
            <p role="status" data-testid="alert-email-test-result" data-ok={testResult.ok} className={testResult.ok ? 'text-sm text-green-300' : 'text-sm text-red-300'}>{testResult.text}</p>
          ) : null}
        </section>

        <section aria-label="Recent sends">
          <h3 className="mb-2 text-sm font-semibold text-gray-200">Recently emailed alerts</h3>
          {(log ?? []).length === 0 ? (
            <EmptyState title="Nothing emailed yet" description="Alerts that have been emailed will be listed here." />
          ) : (
            <div className="overflow-hidden rounded-lg border border-gray-800">
              <table className="w-full text-sm">
                <thead className="bg-gray-900/60 text-xs uppercase tracking-wide text-gray-500">
                  <tr>
                    <th className="px-4 py-2 text-left">Sent</th>
                    <th className="px-4 py-2 text-left">Tenant</th>
                    <th className="px-4 py-2 text-left">Severity</th>
                    <th className="px-4 py-2 text-left">Alert</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800 bg-gray-950/40">
                  {(log ?? []).map((l) => (
                    <tr key={l.alert_id} data-testid="alert-email-log-row">
                      <td className="px-4 py-2 text-xs text-gray-400" suppressHydrationWarning>{formatDistanceToNow(new Date(l.sent_at), { addSuffix: true })}</td>
                      <td className="px-4 py-2 text-gray-300">{l.tenant_name ?? 'unknown tenant'}</td>
                      <td className="px-4 py-2 text-gray-300">{l.severity}</td>
                      <td className="px-4 py-2 text-gray-100">{l.title}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      <ConfirmDialog
        open={confirm !== null}
        title="Send other tenants' alert titles to these addresses?"
        message={`Alert titles from every tenant, with the tenant's name, will be emailed to: ${(confirm?.recipients ?? []).join(', ') || 'nobody'}. Only do this for people who may see all of your customers' alerts.`}
        confirmLabel="Save"
        destructive={false}
        busy={saving}
        onConfirm={() => confirm && void save(confirm)}
        onCancel={() => setConfirm(null)}
      />
    </div>
  );
}
