import type { Metadata } from "next";
import { Suspense } from "react";

import { ClientReview } from "./ClientReview";

export const metadata: Metadata = {
  title: "Client review | Reports | A.C.O.R.N",
};

export default function ClientReviewPage() {
  // ClientReview reads the URL (?client=), which a statically built page must wrap in Suspense.
  return (
    <Suspense fallback={null}>
      <ClientReview />
    </Suspense>
  );
}
