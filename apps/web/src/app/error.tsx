'use client';

import { useEffect } from 'react';
import { ErrorState } from '@/components/ui/ErrorState';

/** Fallback for a render error outside the app shell (login, marketing, tools). */
export default function RootError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error('[aisoc-web] page render failed', error);
  }, [error]);
  return (
    <main className="mx-auto max-w-2xl p-6">
      <ErrorState title="This page hit an error" description="Retry, or go back and try again." error={error} onRetry={reset} />
    </main>
  );
}
