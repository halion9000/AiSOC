'use client';

import { useEffect } from 'react';
import { ErrorState } from '@/components/ui/ErrorState';

/**
 * Catches a render error in any page under the app shell, so one bad value in one view shows a retry card inside the
 * layout (sidebar, tenant picker) instead of replacing the whole console with Next's "This page couldn't load".
 */
export default function AppError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error('[aisoc-web] page render failed', error);
  }, [error]);
  return (
    <div className="p-6">
      <ErrorState
        title="This view hit an error"
        description="The rest of the console still works. Retry, or open another page."
        error={error}
        onRetry={reset}
      />
    </div>
  );
}
