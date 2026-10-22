import type { Metadata } from "next";

import { GuideView } from "@/components/guide/GuideView";

export const metadata: Metadata = {
  title: "User guide | A.C.O.R.N",
};

export default function GuidePage() {
  return <GuideView />;
}
