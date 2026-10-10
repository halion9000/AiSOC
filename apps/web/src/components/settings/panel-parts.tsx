import clsx from 'clsx';
import type { ReactNode } from 'react';

import { apiErrorDetail } from '@/lib/api';

// The chrome every Settings panel shares (moved out of SettingsView.tsx so panels in their own files can use it).

export function PanelHeader({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col gap-3 border-b border-gray-800 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h2 className="text-lg font-semibold text-gray-100">{title}</h2>
        <p className="mt-1 max-w-xl text-sm text-gray-500">{description}</p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-sm font-medium text-gray-300">{label}</span>
      {children}
      {hint ? <span className="text-xs text-gray-500">{hint}</span> : null}
    </label>
  );
}

export function inputClass() {
  return clsx(
    'w-full rounded-lg border border-gray-700 bg-gray-950/60 px-3 py-2 text-sm text-gray-100',
    'placeholder:text-gray-600 focus:border-blue-500/60 focus:outline-none focus:ring-1 focus:ring-blue-500/40',
  );
}

/** What to tell the person when a request failed: the API's own explanation if it gave one, else `fallback`. */
export function errorText(err: unknown, fallback: string): string {
  return apiErrorDetail(err) ?? fallback;
}
