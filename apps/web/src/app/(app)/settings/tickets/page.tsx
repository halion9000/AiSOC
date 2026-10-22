import type { Metadata } from "next";

import { TicketSettings } from "./TicketSettings";

export const metadata: Metadata = {
  title: "Tickets | Settings | A.C.O.R.N",
};

export default function TicketSettingsPage() {
  return <TicketSettings />;
}
