'use client';

import { FrameworkView } from './FrameworkView';

/** /compliance/soc2: the same framework view as every other framework, for SOC 2. */
export function SOC2View() {
  return (
    <div className="p-6">
      <FrameworkView framework="soc2" />
    </div>
  );
}
