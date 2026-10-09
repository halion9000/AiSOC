'use client';

import { useEffect } from 'react';
import { useSelectableTenants } from '@/hooks/useSelectableTenants';

interface TenantScopePickerProps {
  /** The tenant being viewed, or `null` for the caller's own (the default: nothing is sent and the server resolves it from the login). */
  value: string | null;
  onChange: (tenantId: string | null) => void;
  label?: string;
  className?: string;
  /** `dark` for the dark console surfaces (default), `light` for the white ones. */
  tone?: 'dark' | 'light';
}

const TONES = {
  dark: { label: 'text-gray-400', select: 'border-gray-700 bg-gray-900 text-gray-200', note: 'text-amber-300 [&_button]:hover:text-amber-200' },
  light: { label: 'text-gray-500', select: 'border-gray-300 bg-white text-gray-900', note: 'text-amber-700 [&_button]:hover:text-amber-900' },
} as const;

/**
 * Choose which tenant a read-only view is about.
 *
 * It renders NOTHING unless the server says this user may look at other tenants (platform:cross_tenant_query) and there is another one to look at: a control that offers no real choice would only
 * pretend. Choosing your own tenant clears the selection (`null`) rather than naming it. While another tenant is selected a visible note says whose data this is, with a way back, so nobody mistakes
 * a child tenant's numbers for their own. The server decides what is allowed; this only offers what the server listed, and drops a selection the server no longer lists.
 */
export function TenantScopePicker({ value, onChange, label = 'Tenant', className, tone = 'dark' }: TenantScopePickerProps) {
  const { data } = useSelectableTenants();
  const c = TONES[tone];

  const listed = data?.tenants ?? [];
  const stale = value !== null && data !== undefined && !listed.some((t) => t.id === value);
  useEffect(() => {
    if (stale) onChange(null);
  }, [stale, onChange]);

  if (!data || !data.can_select_other_tenants || listed.length < 2) return null;

  const own = data.own_tenant_id;
  const viewing = value !== null && value !== own ? listed.find((t) => t.id === value) : undefined;
  const ordered = [...listed.filter((t) => t.id === own), ...listed.filter((t) => t.id !== own)];

  return (
    <div className={className}>
      <label className={`flex items-center gap-2 text-xs ${c.label}`}>
        <span>{label}</span>
        <select
          value={value ?? own}
          onChange={(e) => onChange(e.target.value === own ? null : e.target.value)}
          className={`rounded-md border px-2 py-1 text-sm ${c.select}`}
        >
          {ordered.map((t) => (
            <option key={t.id} value={t.id}>
              {t.id === own ? `${t.name} (your tenant)` : t.name}
            </option>
          ))}
        </select>
      </label>
      {viewing && (
        <p role="status" className={`mt-1 flex items-center gap-2 text-xs ${c.note}`}>
          <span>Viewing {viewing.name}&apos;s data (read-only).</span>
          <button type="button" onClick={() => onChange(null)} className="underline">
            Back to my tenant
          </button>
        </p>
      )}
    </div>
  );
}
