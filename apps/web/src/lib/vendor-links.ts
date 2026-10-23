/**
 * Where a client's own page is in each tool. A tool's page for a client is addressed by the tool's id for that client (the id the client was mapped by), so a link is a template with that id filled in.
 * A tool with no template here shows its logo without a link: add its template when its page address is known.
 *
 * Some tools live at an address of your own (a ScreenConnect instance, a NinjaOne region). Set NEXT_PUBLIC_VENDOR_LINKS to a JSON object of ``{"vendor": "https://.../{id}"}`` to replace or add templates;
 * only https addresses are used.
 */

const TEMPLATES: Record<string, string> = {
  // Field Effect: https://my.fieldeffect.net/organization/<organization id>/...
  fieldeffect: 'https://my.fieldeffect.net/organization/{id}',
  // NinjaOne: https://app.ninjarmm.com/#/customerDashboard/<organization id>/overview (an account in another region lives on that region's own address: override it)
  ninjaone: 'https://app.ninjarmm.com/#/customerDashboard/{id}/overview',
  // ScreenConnect: a client here is a company (session group); its page is that group under All Machines. The %1F is ScreenConnect's own path separator and must stay as written.
  screenconnect: 'https://liveoakit.screenconnect.com/Host#Access/All%20Machines%1F{id}',
  // HaloPSA: the client's page in your own Halo (customers > the client).
  halopsa: 'https://liveoakit.halopsa.com/customers?mainview=client&inactive=false&hideinternal=false&viewid=0&clientid={id}',
  // Huntress: the organization's command center on your own Huntress account.
  huntress: 'https://goliveoak.huntress.io/org/{id}/command_center?preserve_url_context=true',
  // Huntress SAT (Curricula): the company's dashboard.
  'huntress-sat': 'https://mycurricula.com/company/{id}/dashboard',
  // DNSFilter: the organization's page (the example given ended in /dashboards/<dashboard id>, which belongs to that one dashboard, so the link stops at the organization).
  dnsfilter: 'https://app.dnsfilter.com/organizations/{id}',
  // Timus: a link straight to one customer does not work well yet, so this opens the partner portal's customer list.
  timus: 'https://partners.timusnetworks.com/customers?page=1&limit=50',
  // IT Glue: the organization's page in your own IT Glue.
  itglue: 'https://liveoak.itglue.com/{id}',
  // Datto SaaS Protection (Backupify): the customer's page; the customer id is the one SaaS Protection lists for the domain.
  'datto-saas': 'https://app.backupify.com/office365/customers/{id}',
  // Blumira: the account's dashboard.
  blumira: 'https://app.blumira.com/{id}/dashboard/summary',
  // Addigy: a client here is a policy; its page is the policy.
  addigy: 'https://app.addigy.com/policies/{id}',
};

function overrides(): Record<string, string> {
  const raw = typeof process !== 'undefined' ? process.env.NEXT_PUBLIC_VENDOR_LINKS : undefined;
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object') return {};
    return Object.fromEntries(Object.entries(parsed as Record<string, unknown>).filter(([, v]) => typeof v === 'string' && /^https:\/\/[^\s]+\{id\}/.test(v)) as [string, string][]);
  } catch {
    return {};
  }
}

/** The address of the client's page in this tool, or null when none is known or the id is unusable. Only https addresses are ever made, and the id is always encoded. */
export function vendorClientUrl(vendor: string, vendorClientId: string): string | null {
  const template = { ...TEMPLATES, ...overrides() }[vendor];
  const id = (vendorClientId ?? '').trim();
  // eslint-disable-next-line no-control-regex
  if (!template || id.length === 0 || id.length > 200 || /[\u0000-\u001f\u007f]/.test(id)) return null;
  return template.replace('{id}', encodeURIComponent(id));
}

export const linkableVendors = (): string[] => Object.keys({ ...TEMPLATES, ...overrides() });
