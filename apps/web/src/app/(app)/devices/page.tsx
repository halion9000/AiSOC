import { Suspense } from 'react';
import DevicesView from '@/components/devices/DevicesView';

export const metadata = { title: 'Devices' };

export default function DevicesPage() {
  // DevicesView reads the address (?search=) through the router, which needs a Suspense boundary.
  return (
    <Suspense fallback={null}>
      <DevicesView />
    </Suspense>
  );
}
