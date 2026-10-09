'use client';

import { useTenant } from './TenantProvider';

/**
 * Shown on every page while the console is VIEWING a tenant other than the person's own: whose data this is, that it is read-only (the API refuses writes), and the way back.
 * The switcher used to change only a label, so an operator could believe they were looking at a customer while seeing their own data: this makes the state impossible to miss.
 */
export function TenantViewBanner() {
  const { current, home, viewingOther, returnToHome } = useTenant();
  if (!viewingOther || !current) return null;
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="tenant-view-banner"
      className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-2 text-sm text-fg-primary"
    >
      <p>
        <span className="font-semibold">Viewing {current.name}.</span> Read-only: you can look at this tenant&apos;s data but not change it.
      </p>
      <button
        type="button"
        onClick={returnToHome}
        className="rounded-md border border-amber-500/50 px-3 py-1 text-xs font-medium text-fg-primary transition-colors hover:bg-amber-500/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
      >
        Return to {home?.name ?? 'your tenant'}
      </button>
    </div>
  );
}
