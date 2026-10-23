import { vendorLabel } from './ClientMapping';

const BADGES: Record<string, { text: string; className: string }> = {
  halopsa: { text: 'H', className: 'bg-violet-600/80 text-white' },
  ninjaone: { text: 'N', className: 'bg-emerald-600/80 text-white' },
  huntress: { text: 'Hu', className: 'bg-orange-600/80 text-white' },
  petra: { text: 'P', className: 'bg-sky-600/80 text-white' },
  blumira: { text: 'B', className: 'bg-cyan-600/80 text-white' },
  addigy: { text: 'A', className: 'bg-indigo-600/80 text-white' },
  liongard: { text: 'L', className: 'bg-teal-600/80 text-white' },
  fieldeffect: { text: 'F', className: 'bg-blue-600/80 text-white' },
  dnsfilter: { text: 'DNS', className: 'bg-amber-600/80 text-white' },
  auvik: { text: 'Av', className: 'bg-lime-700/80 text-white' },
  unifi: { text: 'U', className: 'bg-blue-500/80 text-white' },
  slide: { text: 'Sl', className: 'bg-sky-600/80 text-white' },
  'huntress-sat': { text: 'Hs', className: 'bg-orange-600/80 text-white' },
  itglue: { text: 'IT', className: 'bg-indigo-600/80 text-white' },
  autoelevate: { text: 'AE', className: 'bg-rose-600/80 text-white' },
  cipp: { text: 'C', className: 'bg-orange-500/80 text-white' },
  screenconnect: { text: 'SC', className: 'bg-sky-700/80 text-white' },
  vciotoolbox: { text: 'vC', className: 'bg-blue-800/80 text-white' },
};

const LOGOS = new Set(['halopsa', 'ninjaone', 'huntress', 'petra', 'addigy', 'liongard', 'threatmate', 'blumira', 'fieldeffect', 'dnsfilter', 'autoelevate', 'cipp', 'screenconnect', 'vciotoolbox']);

/** Halo first, then the rest in one fixed order so every row lines up; tools not listed follow alphabetically. */
export const VENDOR_ORDER = ['halopsa', 'ninjaone', 'huntress', 'threatmate', 'addigy', 'petra', 'liongard', 'blumira', 'fieldeffect', 'dnsfilter', 'auvik', 'unifi', 'slide', 'huntress-sat', 'itglue', 'autoelevate', 'cipp', 'screenconnect', 'vciotoolbox'];

export function orderSources(sources: string[]): string[] {
  const rank = (v: string) => {
    const i = VENDOR_ORDER.indexOf(v);
    return i === -1 ? VENDOR_ORDER.length : i;
  };
  return [...new Set(sources)].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

/** A small badge for the tool a client came from; hover shows the full name. */
export default function VendorBadge({ vendor, size = 'sm', struck }: { vendor: string; size?: 'sm' | 'lg'; struck?: string }) {
  if (struck) {
    // A red line through the badge: this tool has not seen the device for a while (the text says how long).
    return (
      <span className="relative inline-flex shrink-0" title={struck} data-testid="struck-badge" data-vendor={vendor}>
        <span className="opacity-60">
          <VendorBadge vendor={vendor} size={size} />
        </span>
        <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox="0 0 24 24" aria-hidden="true">
          <line x1="3" y1="21" x2="21" y2="3" stroke="#ef4444" strokeWidth="2.5" strokeLinecap="round" />
        </svg>
      </span>
    );
  }
  const label = vendorLabel(vendor);
  const box = size === 'lg' ? 'h-10 w-10 rounded-xl' : 'h-6 w-6 rounded-md';
  const b = BADGES[vendor] ?? { text: label.charAt(0).toUpperCase(), className: 'bg-gray-600 text-white' };
  if (LOGOS.has(vendor)) {
    return (
      // eslint-disable-next-line @next/next/no-img-element
      <img src={`/vendors/${vendor}.png`} alt={label} title={label} className={`${box} shrink-0 bg-white/90 object-contain p-0.5`} />
    );
  }
  return (
    <span
      title={label}
      aria-label={label}
      role="img"
      className={`inline-flex ${size === 'lg' ? 'h-10 min-w-10 rounded-xl text-sm' : 'h-6 min-w-6 rounded-md text-[11px]'} shrink-0 items-center justify-center px-1 font-semibold ${b.className}`}
    >
      {b.text}
    </span>
  );
}
