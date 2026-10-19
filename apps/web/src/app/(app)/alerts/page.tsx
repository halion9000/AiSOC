import { Suspense } from 'react';
import { AlertsView } from '@/components/alerts/AlertsView';

export const metadata = {
  title: 'Alerts',
};

export default function AlertsPage() {
  // AlertsView reads the address (?device=, ?status=) through the router, which needs a Suspense boundary.
  return (
    <Suspense fallback={null}>
      <AlertsView />
    </Suspense>
  );
}
