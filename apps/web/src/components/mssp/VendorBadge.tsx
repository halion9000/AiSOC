import { vendorLabel } from './ClientMapping';

const BADGES: Record<string, { text: string; className: string }> = {
  halopsa: { text: 'H', className: 'bg-violet-600/80 text-white' },
  ninjaone: { text: 'N', className: 'bg-emerald-600/80 text-white' },
  huntress: { text: 'Hu', className: 'bg-orange-600/80 text-white' },
  petra: { text: 'P', className: 'bg-sky-600/80 text-white' },
  blumira: { text: 'B', className: 'bg-cyan-600/80 text-white' },
};

/** A small badge for the tool a client came from; hover shows the full name. */
export default function VendorBadge({ vendor }: { vendor: string }) {
  const label = vendorLabel(vendor);
  const b = BADGES[vendor] ?? { text: label.charAt(0).toUpperCase(), className: 'bg-gray-600 text-white' };
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
