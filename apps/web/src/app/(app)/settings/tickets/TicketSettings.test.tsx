import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const authFetch = vi.fn();
vi.mock("@/lib/auth-session", () => ({ authFetch: (...a: unknown[]) => authFetch(...a) }));

import { TicketSettings } from "./TicketSettings";

const reply = (body: unknown, status = 200) => ({ ok: status < 400, status, json: () => Promise.resolve(body), text: () => Promise.resolve(JSON.stringify(body)) });

beforeEach(() => authFetch.mockReset());
afterEach(() => cleanup());

describe("TicketSettings", () => {
  it("shows the default status and saves a different one", async () => {
    authFetch.mockResolvedValueOnce(reply({ close_status: "Tech Updated", is_default: true, default: "Tech Updated" }));
    render(<TicketSettings />);
    expect(await screen.findByTestId("current")).toHaveTextContent('"Tech Updated" (the default)');
    authFetch.mockResolvedValueOnce(reply({ close_status: "Closed", is_default: false, default: "Tech Updated" }));
    const user = userEvent.setup();
    const input = screen.getByLabelText("Ticket status");
    await user.clear(input);
    await user.type(input, "Closed");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(authFetch).toHaveBeenLastCalledWith("/api/v1/tenant-settings/tickets", expect.objectContaining({ method: "PUT", body: JSON.stringify({ close_status: "Closed" }) })));
    expect(await screen.findByTestId("current")).toHaveTextContent('"Closed".');
  });

  it("offers to go back to the default only when a choice has been made, and does so", async () => {
    authFetch.mockResolvedValueOnce(reply({ close_status: "Closed", is_default: false, default: "Tech Updated" }));
    render(<TicketSettings />);
    await screen.findByTestId("current");
    authFetch.mockResolvedValueOnce(reply({ close_status: "Tech Updated", is_default: true, default: "Tech Updated" }));
    await userEvent.setup().click(screen.getByRole("button", { name: "Use the default" }));
    await waitFor(() => expect(authFetch).toHaveBeenLastCalledWith("/api/v1/tenant-settings/tickets", expect.objectContaining({ method: "DELETE" })));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Use the default" })).not.toBeInTheDocument());
  });

  it("will not save an empty name and shows the API's reason when it refuses", async () => {
    authFetch.mockResolvedValueOnce(reply({ close_status: "Tech Updated", is_default: true, default: "Tech Updated" }));
    render(<TicketSettings />);
    await screen.findByTestId("current");
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText("Ticket status"));
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    await user.type(screen.getByLabelText("Ticket status"), "X");
    authFetch.mockResolvedValueOnce(reply({ detail: "Not allowed" }, 403));
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
