import { vendorLabel } from './ClientMapping';

const BADGES: Record<string, { text: string; className: string }> = {
  halopsa: { text: 'H', className: 'bg-violet-600/80 text-white' },
  ninjaone: { text: 'N', className: 'bg-emerald-600/80 text-white' },
  huntress: { text: 'Hu', className: 'bg-orange-600/80 text-white' },
  petra: { text: 'P', className: 'bg-sky-600/80 text-white' },
  blumira: { text: 'B', className: 'bg-cyan-600/80 text-white' },
  addigy: { text: 'A', className: 'bg-indigo-600/80 text-white' },
  liongard: { text: 'L', className: 'bg-teal-600/80 text-white' },
};

const LOGOS = new Set(['halopsa', 'ninjaone', 'huntress', 'petra', 'addigy', 'liongard', 'threatmate']);

/** Halo first, then the rest in one fixed order so every row lines up; tools not listed follow alphabetically. */
export const VENDOR_ORDER = ['halopsa', 'ninjaone', 'huntress', 'threatmate', 'addigy', 'petra', 'liongard', 'blumira'];

export function orderSources(sources: string[]): string[] {
  const rank = (v: string) => {
    const i = VENDOR_ORDER.indexOf(v);
    return i === -1 ? VENDOR_ORDER.length : i;
  };
  return [...new Set(sources)].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

/** A small badge for the tool a client came from; hover shows the full name. */
export default function VendorBadge({ vendor }: { vendor: string }) {
  const label = vendorLabel(vendor);
  const b = BADGES[vendor] ?? { text: label.charAt(0).toUpperCase(), className: 'bg-gray-600 text-white' };
  if (LOGOS.has(vendor)) {
    return (
      // eslint-disable-next-line @next/next/no-img-element
      <img src={`/vendors/${vendor}.png`} alt={label} title={label} className="h-6 w-6 shrink-0 rounded-md bg-white/90 object-contain p-0.5" />
    );
  }
  return (
    <span
      title={label}
      aria-label={label}
      role="img"
      className={`inline-flex h-6 min-w-6 items-center justify-center rounded-md px-1 text-[11px] font-semibold ${b.className}`}
    >
      {b.text}
    </span>
  );
}
