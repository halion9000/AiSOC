import type { Metadata } from "next";

import { ClientPosture } from "./ClientPosture";

export const metadata: Metadata = {
  title: "Client posture | Settings | A.C.O.R.N",
};

export default function ClientPosturePage() {
  return <ClientPosture />;
}
