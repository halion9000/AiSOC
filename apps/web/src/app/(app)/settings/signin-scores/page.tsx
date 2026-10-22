import type { Metadata } from "next";

import { SigninScores } from "./SigninScores";

export const metadata: Metadata = {
  title: "Sign-in scores | Settings | A.C.O.R.N",
};

export default function SigninScoresPage() {
  return <SigninScores />;
}
