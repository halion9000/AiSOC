import type { Metadata } from "next";

import { ClientPosture } from "./ClientPosture";

export const metadata: Metadata = {
  title: "Client posture | Settings | AiSOC",
};

export default function ClientPosturePage() {
  return <ClientPosture />;
}
