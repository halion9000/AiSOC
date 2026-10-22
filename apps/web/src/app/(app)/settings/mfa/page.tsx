import type { Metadata } from "next";
import { Suspense } from "react";

import { MfaStatus } from "./MfaStatus";

export const metadata: Metadata = {
  title: "Multi-factor status | Settings | A.C.O.R.N",
};

export default function MfaStatusPage() {
  // MfaStatus reads the URL (?client=&which=), which a statically built page must wrap in Suspense.
  return (
    <Suspense fallback={null}>
      <MfaStatus />
    </Suspense>
  );
}
