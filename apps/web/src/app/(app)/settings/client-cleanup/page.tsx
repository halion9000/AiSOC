import type { Metadata } from "next";

import { ClientCleanup } from "./ClientCleanup";

export const metadata: Metadata = {
  title: "Client cleanup | Settings | A.C.O.R.N",
};

export default function ClientCleanupPage() {
  return <ClientCleanup />;
}
