'use client';

import { useState } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import { formatDistanceToNow } from 'date-fns';

import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { Skeleton } from '@/components/ui/Skeleton';
import { useTenant } from '@/components/layout/TenantProvider';
import { tenantAccessApi, type AccessLevel } from '@/lib/api';
import { Field, PanelHeader, errorText, inputClass } from './panel-parts';

/** What a person may do in a tenant they were granted, in the words shown on screen. */
export function levelLabel(level: AccessLevel): string {
  return level === 'full' ? 'Full access' : 'Read-only';
}

const FULL_ACCESS_NOTE =
  "With full access the person can change things in this tenant using their own role's permissions, never more. They still cannot manage users, API keys or who has access. Every change is recorded in this tenant's audit log.";

function LevelPill({ level }: { level: AccessLevel }) {
  return (
    <span
      data-testid="access-level"
      data-level={level}
      className={
        level === 'full'
          ? 'rounded bg-red-500/15 px-2 py-0.5 text-xs font-medium text-red-200 ring-1 ring-red-500/40'
          : 'rounded bg-gray-800 px-2 py-0.5 text-xs font-medium text-gray-300 ring-1 ring-gray-700'
      }
    >
      {levelLabel(level)}
    </span>
  );
}

type Pending =
  | { kind: 'grant'; account: string; level: AccessLevel; scope: 'tenant' | 'all'; tenantId?: string }
  | { kind: 'revoke'; account: string; scope: 'tenant' | 'all'; tenantId?: string };

/**
 * Who has been GRANTED access to a tenant (people who belong to another one), and at which level; and, for a platform administrator, who holds EVERY tenant.
 * The server decides what is allowed (and says why when it is not); this only offers what the server's own rule says the person may manage.
 */
export function TenantAccessPanel({ canGrantAll }: { canGrantAll: boolean }) {
  const { viewingOther, home } = useTenant();
  if (viewingOther) {
    return (
      <div>
        <PanelHeader title="Tenant access" description="Who may work in which tenant." />
        <p data-testid="viewing-other-notice" className="px-6 py-5 text-sm text-amber-200">
          Access is managed from your own tenant. Return to {home?.name ?? 'your tenant'} (the banner above has the button) and open this page again.
        </p>
      </div>
    );
  }
  return <Inner canGrantAll={canGrantAll} />;
}

function Inner({ canGrantAll }: { canGrantAll: boolean }) {
  const { data: manageable, isLoading: loadingTenants, error: tenantsError } = useSWR('settings:tenant-manageable', () => tenantAccessApi.manageable());
  const [chosen, setChosen] = useState<string | null>(null);
  const tenants = manageable?.tenants ?? [];
  const tenantId = chosen ?? tenants[0]?.id ?? null;
  const tenantName = (id: string) => tenants.find((t) => t.id === id)?.name ?? 'another tenant';

  const { data: grants, isLoading: loadingGrants, mutate: reloadGrants } = useSWR(tenantId ? ['settings:tenant-access', tenantId] : null, () => tenantAccessApi.list(tenantId as string));
  const { data: everyTenant, mutate: reloadAll } = useSWR(canGrantAll ? 'settings:all-tenant-access' : null, () => tenantAccessApi.listAll());

  const [name, setName] = useState('');
  const [level, setLevel] = useState<AccessLevel>('view');
  const [allName, setAllName] = useState('');
  const [allLevel, setAllLevel] = useState<AccessLevel | ''>('');
  const [error, setError] = useState<string | null>(null);
  const [allError, setAllError] = useState<string | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [busy, setBusy] = useState(false);

  const perform = async (action: Pending) => {
    setBusy(true);
    const report = action.scope === 'all' ? setAllError : setError;
    try {
      if (action.kind === 'grant') {
        if (action.scope === 'all') await tenantAccessApi.grantAll(action.account, action.level);
        else await tenantAccessApi.grant(action.tenantId as string, action.account, action.level);
        toast.success(`${action.account}: ${levelLabel(action.level).toLowerCase()}`);
        report(null);
        if (action.scope === 'all') {
          setAllName('');
          setAllLevel('');
        } else {
          setName('');
          setLevel('view');
        }
      } else {
        if (action.scope === 'all') await tenantAccessApi.revokeAll(action.account);
        else await tenantAccessApi.revoke(action.tenantId as string, action.account);
        toast.success(`${action.account}: access removed`);
        report(null);
      }
    } catch (err) {
      report(errorText(err, action.kind === 'grant' ? 'The access could not be changed.' : 'The access could not be removed.'));
    } finally {
      setBusy(false);
      setPending(null);
      void (action.scope === 'all' ? reloadAll() : reloadGrants());
    }
  };

  /** Anything that gives MORE access, and everything for every tenant, asks first; giving less happens at once. */
  const request = (action: Pending) => {
    const needsAsking = action.kind === 'revoke' || action.scope === 'all' || action.level === 'full';
    if (needsAsking) setPending(action);
    else void perform(action);
  };

  const submitGrant = () => {
    const account = name.trim();
    if (!account) return setError('Type the account name of the person.');
    if (!tenantId) return;
    setError(null);
    request({ kind: 'grant', account, level, scope: 'tenant', tenantId });
  };
  const submitAll = () => {
    const account = allName.trim();
    if (!account) return setAllError('Type the account name of the person.');
    if (!allLevel) return setAllError('Choose a level: read-only or full access.');
    setAllError(null);
    request({ kind: 'grant', account, level: allLevel, scope: 'all' });
  };

  const dialog = (() => {
    if (!pending) return null;
    const where = pending.scope === 'all' ? 'EVERY tenant, including ones created later' : tenantName(pending.tenantId as string);
    if (pending.kind === 'revoke') return { title: 'Remove access?', message: `${pending.account} will no longer be able to work in ${where}. This takes effect on their next request.`, confirmLabel: 'Remove access' };
    return {
      title: pending.level === 'full' ? 'Give full access?' : 'Give access to every tenant?',
      message: `Give ${pending.account} ${levelLabel(pending.level).toLowerCase()} to ${where}? ${pending.level === 'full' ? FULL_ACCESS_NOTE : 'They will be able to look at all of it, and change nothing.'}`,
      confirmLabel: pending.level === 'full' ? 'Give full access' : 'Give access',
    };
  })();

  return (
    <div>
      <PanelHeader
        title="Tenant access"
        description="Let people who belong to another tenant work in this one: read-only, or with full access. You decide for the tenants you manage; every change is recorded in that tenant's audit log."
      />
      <div className="space-y-6 px-6 py-5">
        {loadingTenants && !manageable ? (
          <Skeleton className="h-14 w-full rounded-lg" />
        ) : tenantsError ? (
          <p role="alert" className="text-sm text-red-300">{errorText(tenantsError, 'Your tenants could not be loaded.')}</p>
        ) : tenants.length === 0 ? (
          <EmptyState title="You cannot manage anyone's access" description="Managing who may work in a tenant needs permission to manage users in it." />
        ) : (
          <>
            <section aria-label="Access to one tenant" className="space-y-4">
              {tenants.length > 1 ? (
                <Field label="Tenant">
                  <select aria-label="Tenant" className={inputClass()} value={tenantId ?? ''} onChange={(e) => setChosen(e.target.value)}>
                    {tenants.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.name}
                        {t.relationship === 'self' ? ' (yours)' : ''}
                      </option>
                    ))}
                  </select>
                </Field>
              ) : (
                <p className="text-sm text-gray-300">
                  Access to <span className="font-medium">{tenantName(tenantId ?? '')}</span>
                </p>
              )}

              <div className="flex flex-col gap-3 rounded-lg border border-gray-800 bg-gray-950/40 p-4 sm:flex-row sm:items-end">
                <Field label="Account name">
                  <input aria-label="Account name" className={inputClass()} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. hal.liveoak" />
                </Field>
                <Field label="Access level">
                  <select aria-label="Access level" className={inputClass()} value={level} onChange={(e) => setLevel(e.target.value as AccessLevel)}>
                    <option value="view">Read-only</option>
                    <option value="full">Full access</option>
                  </select>
                </Field>
                <button type="button" onClick={submitGrant} disabled={busy} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50">
                  Grant access
                </button>
              </div>
              {level === 'full' ? <p className="text-xs text-red-200">{FULL_ACCESS_NOTE}</p> : null}
              {error ? <p role="alert" data-testid="access-error" className="text-sm text-red-300">{error}</p> : null}

              {loadingGrants && !grants ? (
                <Skeleton className="h-14 w-full rounded-lg" />
              ) : (grants ?? []).length === 0 ? (
                <EmptyState title="Nobody from another tenant has access" description="People you grant access to will be listed here." />
              ) : (
                <div className="overflow-hidden rounded-lg border border-gray-800">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-900/60 text-xs uppercase tracking-wide text-gray-500">
                      <tr>
                        <th className="px-4 py-2 text-left">Person</th>
                        <th className="px-4 py-2 text-left">Belongs to</th>
                        <th className="px-4 py-2 text-left">Access</th>
                        <th className="px-4 py-2 text-left">Granted</th>
                        <th className="px-4 py-2 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800 bg-gray-950/40">
                      {(grants ?? []).map((g) => (
                        <tr key={g.user_id} data-testid="access-row">
                          <td className="px-4 py-3">
                            <div className="font-medium text-gray-100">{g.account_name}</div>
                            {g.email ? <div className="text-xs text-gray-500">{g.email}</div> : null}
                          </td>
                          <td className="px-4 py-3 text-gray-300">{tenantName(g.home_tenant_id)}</td>
                          <td className="px-4 py-3"><LevelPill level={g.access} /></td>
                          <td className="px-4 py-3 text-xs text-gray-400" suppressHydrationWarning>
                            {g.granted_by} · {formatDistanceToNow(new Date(g.created_at), { addSuffix: true })}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <div className="flex justify-end gap-2">
                              <button
                                type="button"
                                onClick={() => request({ kind: 'grant', account: g.account_name, level: g.access === 'full' ? 'view' : 'full', scope: 'tenant', tenantId: tenantId as string })}
                                className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-800"
                              >
                                {g.access === 'full' ? 'Make read-only' : 'Give full access'}
                              </button>
                              <button
                                type="button"
                                onClick={() => request({ kind: 'revoke', account: g.account_name, scope: 'tenant', tenantId: tenantId as string })}
                                className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs text-red-200 hover:bg-red-500/20"
                              >
                                Revoke
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            {canGrantAll ? (
              <section aria-label="Access to every tenant" className="space-y-4 rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
                <div>
                  <h3 className="text-base font-semibold text-gray-100">Every tenant</h3>
                  <p className="mt-1 text-sm text-gray-400">
                    Platform administrators only. Gives a person access to every tenant, including ones created later. Choose the level on purpose: there is no default.
                  </p>
                </div>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
                  <Field label="Account name">
                    <input aria-label="Account name for every tenant" className={inputClass()} value={allName} onChange={(e) => setAllName(e.target.value)} placeholder="e.g. hal.liveoak" />
                  </Field>
                  <Field label="Access level">
                    <select aria-label="Access level for every tenant" className={inputClass()} value={allLevel} onChange={(e) => setAllLevel(e.target.value as AccessLevel | '')}>
                      <option value="">Choose a level…</option>
                      <option value="view">Read-only</option>
                      <option value="full">Full access</option>
                    </select>
                  </Field>
                  <button type="button" onClick={submitAll} disabled={busy} className="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white hover:bg-amber-500 disabled:opacity-50">
                    Grant every tenant
                  </button>
                </div>
                {allError ? <p role="alert" data-testid="all-access-error" className="text-sm text-red-300">{allError}</p> : null}
                {(everyTenant ?? []).length === 0 ? (
                  <p className="text-sm text-gray-500">Nobody holds every tenant.</p>
                ) : (
                  <ul className="divide-y divide-gray-800 rounded-lg border border-gray-800 bg-gray-950/40 text-sm">
                    {(everyTenant ?? []).map((g) => (
                      <li key={g.user_id} data-testid="all-access-row" className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                        <div>
                          <span className="font-medium text-gray-100">{g.account_name}</span> <LevelPill level={g.access} />
                          <div className="text-xs text-gray-500">{g.granted_by} · {formatDistanceToNow(new Date(g.created_at), { addSuffix: true })}</div>
                        </div>
                        <div className="flex gap-2">
                          <button
                            type="button"
                            onClick={() => request({ kind: 'grant', account: g.account_name, level: g.access === 'full' ? 'view' : 'full', scope: 'all' })}
                            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-800"
                          >
                            {g.access === 'full' ? 'Make read-only' : 'Give full access'}
                          </button>
                          <button
                            type="button"
                            onClick={() => request({ kind: 'revoke', account: g.account_name, scope: 'all' })}
                            className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs text-red-200 hover:bg-red-500/20"
                          >
                            Revoke
                          </button>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            ) : null}
          </>
        )}
      </div>

      <ConfirmDialog
        open={pending !== null}
        title={dialog?.title ?? ''}
        message={dialog?.message ?? ''}
        confirmLabel={dialog?.confirmLabel}
        busy={busy}
        onConfirm={() => pending && void perform(pending)}
        onCancel={() => setPending(null)}
      />
    </div>
  );
}
