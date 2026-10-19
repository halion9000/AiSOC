import type { Metadata } from "next";

import { MfaStatus } from "./MfaStatus";

export const metadata: Metadata = {
  title: "Multi-factor status | Settings | AiSOC",
};

export default function MfaStatusPage() {
  return <MfaStatus />;
}
