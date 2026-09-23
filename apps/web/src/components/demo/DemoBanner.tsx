'use client';

/**
 * DemoBanner — top-of-page strip rendered on the hosted demo at tryaisoc.com.
 *
 * Sits inside `AppShell` above the TopBar so it covers every authenticated
 * page. Renders nothing when `NEXT_PUBLIC_DEMO_MODE !== 'true'`, so self-hosted
 * deployments never see it.
 *
 * Accessibility: announced via role="status" so screen readers pick up the
 * "writes are disabled" message at page load. Not dismissible — visitors have
 * to know writes will 403, otherwise they'll think the app is broken.
 *
 * Hal, 2026-09-19: removed entirely for this self-hosted fork — the banner's
 * own wording ("resets daily", "write actions are disabled") describes the
 * public tryaisoc.com demo specifically and doesn't apply to a private
 * self-host: AISOC_DEMO_MODE (the separate backend flag that middleware/
 * demo_mode.py actually enforces writes with) defaults to false and was
 * never set in infra/compose/docker-compose.demo.yml, and there's no reset
 * job anywhere in this self-host compose setup either - so both claims were
 * simply inaccurate here, not a real restriction being described.
 * Unconditional `return null` rather than flipping NEXT_PUBLIC_DEMO_MODE
 * itself off deliberately: that same flag is what DemoAutoLogin.tsx checks
 * to silently log in as the seeded demo user - turning it off would kill
 * that working login-free flow as a side effect of removing an unrelated
 * banner.
 */

export function DemoBanner() {
  return null;
}
