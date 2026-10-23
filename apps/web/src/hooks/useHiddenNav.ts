'use client';

import { useMemo } from 'react';
import useSWR from 'swr';
import { authFetch } from '@/lib/auth-session';
import { toHiddenSet } from '@/lib/nav-visibility';

/** What the signed-in person's roles hide in the console (GET /auth/me, ``hidden_nav``). Nothing is hidden while it loads or if it cannot be read: a failure must not take pages away. */
export function useHiddenNav(): ReadonlySet<string> {
  const { data } = useSWR<string[]>(
    'auth-me-hidden-nav',
    async () => {
      const res = await authFetch('/api/v1/auth/me');
      if (!res.ok) return [];
      const body = (await res.json()) as { hidden_nav?: unknown };
      return [...toHiddenSet(body.hidden_nav)];
    },
    { revalidateOnFocus: false, shouldRetryOnError: false, dedupingInterval: 60_000 },
  );
  return useMemo(() => new Set(data ?? []), [data]);
}
