import type { Metadata } from "next";

import { AutoCloseSettings } from "./AutoCloseSettings";

export const metadata: Metadata = {
  title: "Auto-close | Settings | AiSOC",
};

export default function TriageSettingsPage() {
  return <AutoCloseSettings />;
}
