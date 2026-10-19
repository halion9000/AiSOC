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
  // No logo file yet: a lettered badge until public/vendors/dnsfilter.png is added (then add 'dnsfilter' to LOGOS below).
  dnsfilter: { text: 'DNS', className: 'bg-amber-600/80 text-white' },
  autoelevate: { text: 'AE', className: 'bg-rose-600/80 text-white' },
};

const LOGOS = new Set(['halopsa', 'ninjaone', 'huntress', 'petra', 'addigy', 'liongard', 'threatmate', 'blumira', 'fieldeffect']);

/** Halo first, then the rest in one fixed order so every row lines up; tools not listed follow alphabetically. */
export const VENDOR_ORDER = ['halopsa', 'ninjaone', 'huntress', 'threatmate', 'addigy', 'petra', 'liongard', 'blumira', 'fieldeffect', 'dnsfilter', 'autoelevate'];

export function orderSources(sources: string[]): string[] {
  const rank = (v: string) => {
    const i = VENDOR_ORDER.indexOf(v);
    return i === -1 ? VENDOR_ORDER.length : i;
  };
  return [...new Set(sources)].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

/** A small badge for the tool a client came from; hover shows the full name. */
export default function VendorBadge({ vendor, size = 'sm' }: { vendor: string; size?: 'sm' | 'lg' }) {
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
