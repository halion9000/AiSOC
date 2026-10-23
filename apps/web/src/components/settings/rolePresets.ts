/**
 * Starting points for a new role: what to hide and which permissions to start with. A preset only fills the form; nothing is saved until the administrator presses Create, and every permission it
 * names is looked up in the real list first, so one the install does not have is simply left out.
 */

export interface RolePreset {
  key: string;
  label: string;
  description: string;
  hidden: string[];
  /** Permission names to tick. A trailing ``*`` after the colon means every permission with that action, e.g. ``*:read``. */
  permissions: string[];
}

export const ROLE_PRESETS: RolePreset[] = [
  {
    key: 'read-only-analyst',
    label: 'Read-only analyst',
    description: 'Sees alerts, cases and clients and can read everything, but changes nothing. Automation and platform administration are hidden.',
    hidden: ['section:Automation', 'section:Platform'],
    permissions: ['*:read'],
  },
  {
    key: 'client-reviewer',
    label: 'Client reviewer (vCIO)',
    description: 'Works on client reviews and posture. Threat operations, intelligence, automation and platform settings are hidden.',
    hidden: ['section:Threat Operations', 'section:Intelligence', 'section:Automation', '/connectors', '/costs', '/audit', '/settings', '/onboarding'],
    permissions: ['*:read'],
  },
  {
    key: 'auditor',
    label: 'Auditor',
    description: 'Reads compliance, audit and reports. Cannot change anything, and automation and intelligence are hidden.',
    hidden: ['section:Automation', 'section:Intelligence', '/queue', '/hunt', '/explore'],
    permissions: ['compliance:read', 'audit:read', 'cases:read', 'alerts:read', 'reports:read'],
  },
];

/** The ids of the permissions a preset asks for that exist in ``all``. */
export function presetPermissionIds(preset: RolePreset, all: { id: string; name: string }[]): string[] {
  const wanted = new Set<string>();
  for (const spec of preset.permissions) {
    if (spec.startsWith('*:')) {
      const action = spec.slice(2);
      for (const p of all) if (p.name.endsWith(`:${action}`)) wanted.add(p.id);
    } else {
      const hit = all.find((p) => p.name === spec);
      if (hit) wanted.add(hit.id);
    }
  }
  return [...wanted];
}
