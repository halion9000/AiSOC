import type { Metadata } from "next";

import { AutoCloseSettings } from "./AutoCloseSettings";

export const metadata: Metadata = {
  title: "Auto-close | Settings | A.C.O.R.N",
};

export default function TriageSettingsPage() {
  return <AutoCloseSettings />;
}
