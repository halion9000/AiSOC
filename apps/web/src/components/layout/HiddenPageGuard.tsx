'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useHiddenNav } from '@/hooks/useHiddenNav';
import { isPathHidden } from './Sidebar';

/**
 * Shows the page, or says plainly that this person's role hides it. Typing the address of a hidden page does not open it. This is about what is shown: the server still checks permissions on every request.
 */
export function HiddenPageGuard({ children }: { children: React.ReactNode }) {
  const pathname = usePathname() ?? '';
  const hidden = useHiddenNav();
  if (!isPathHidden(hidden, pathname)) return <>{children}</>;
  return (
    <div role="status" className="mx-auto mt-16 max-w-md rounded-lg border border-gray-800 bg-gray-900/60 p-6 text-center">
      <h1 className="text-lg font-semibold text-gray-100">This page is hidden for your role</h1>
      <p className="mt-2 text-sm text-gray-400">An administrator has hidden it from the roles you hold. Ask them if you need it.</p>
      <Link href="/dashboard" className="mt-4 inline-block rounded-md bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600">
        Back to the dashboard
      </Link>
    </div>
  );
}
