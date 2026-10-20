import type { Metadata } from "next";

import { GuideView } from "@/components/guide/GuideView";

export const metadata: Metadata = {
  title: "User guide | AiSOC",
};

export default function GuidePage() {
  return <GuideView />;
}
