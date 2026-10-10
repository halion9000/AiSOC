'use client';

import { useTenant } from './TenantProvider';

/**
 * Shown on every page while the console is on a tenant other than the person's own: whose data this is, WHAT THEY MAY DO THERE, and the way back.
 *
 * With `view` access it is read-only (the API refuses writes). With `full` access the person is WORKING in that tenant: their changes are made there and recorded in that tenant's own audit log, so the banner says so plainly and looks different from a read-only view: nobody should
 * believe they are looking at a customer while changing it, or the reverse. When the level could not be loaded it says neither, only whose tenant this is.
 *
 * The switcher used to change only a label, so an operator could believe they were looking at a customer while seeing their own data: this makes the state impossible to miss.
 */
export function TenantViewBanner() {
  const { current, home, viewingOther, returnToHome } = useTenant();
  if (!viewingOther || !current) return null;
  const working = current.access === 'full';
  const box = working ? 'border-red-500/50 bg-red-500/10' : 'border-amber-500/40 bg-amber-500/10';
  const button = working ? 'border-red-500/60 hover:bg-red-500/20' : 'border-amber-500/50 hover:bg-amber-500/20';
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="tenant-view-banner"
      data-access={current.access ?? 'unknown'}
      className={`mb-4 flex flex-wrap items-center justify-between gap-3 rounded-md border px-4 py-2 text-sm text-fg-primary ${box}`}
    >
      <p>
        {working ? (
          <>
            <span className="font-semibold">Working in {current.name} with full access.</span> Your changes are made in this tenant and recorded in its audit log.
          </>
        ) : current.access === 'view' ? (
          <>
            <span className="font-semibold">Viewing {current.name}.</span> Read-only: you can look at this tenant&apos;s data but not change it.
          </>
        ) : (
          <span className="font-semibold">Viewing {current.name}.</span>
        )}
      </p>
      <button
        type="button"
        onClick={returnToHome}
        className={`rounded-md border px-3 py-1 text-xs font-medium text-fg-primary transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 ${button}`}
      >
        Return to {home?.name ?? 'your tenant'}
      </button>
    </div>
  );
}
