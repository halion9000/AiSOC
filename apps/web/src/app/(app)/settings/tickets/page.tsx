import type { Metadata } from "next";

import { TicketSettings } from "./TicketSettings";

export const metadata: Metadata = {
  title: "Tickets | Settings | AiSOC",
};

export default function TicketSettingsPage() {
  return <TicketSettings />;
}
