import type { Metadata } from "next";

import { PlatformHealth } from "./PlatformHealth";

export const metadata: Metadata = {
  title: "Platform Health | Settings | AiSOC",
};

export default function PlatformHealthPage() {
  return <PlatformHealth />;
}
