import type { Metadata } from "next";

import { SecureScore } from "./SecureScore";

export const metadata: Metadata = {
  title: "Microsoft Secure Score | Settings | AiSOC",
};

export default function SecureScorePage() {
  return <SecureScore />;
}
