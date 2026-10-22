import type { Metadata } from "next";

import { PlatformHealth } from "./PlatformHealth";

export const metadata: Metadata = {
  title: "Platform Health | Settings | A.C.O.R.N",
};

export default function PlatformHealthPage() {
  return <PlatformHealth />;
}
