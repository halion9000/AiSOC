import type { Metadata, Viewport } from 'next';
import { ResponderShell } from '@/components/responder/ResponderShell';

export const metadata: Metadata = {
  title: {
    default: 'Responder | A.C.O.R.N',
    template: '%s | A.C.O.R.N Responder',
  },
  description:
    'Mobile-first A.C.O.R.N responder. Triage alerts, approve agent actions, page on-call — all from your phone.',
};

export const viewport: Viewport = {
  themeColor: '#0a0d14',
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
};

export default function ResponderLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <ResponderShell>{children}</ResponderShell>;
}
