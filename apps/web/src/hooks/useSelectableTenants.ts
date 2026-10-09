'use client';

import useSWR from 'swr';
import { tenantsApi, type SelectableTenantsResponse } from '@/lib/api';

/**
 * The tenants this user may choose between in a tenant picker (GET /api/v1/tenants/selectable).
 * Their own tenant always; every other tenant only if the server says they may look at others. The list barely changes, so it is not refetched on focus.
 */
export function useSelectableTenants() {
  return useSWR<SelectableTenantsResponse>('tenants-selectable', () => tenantsApi.selectable(), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  });
}
