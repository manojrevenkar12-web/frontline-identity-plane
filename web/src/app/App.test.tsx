import "@testing-library/jest-dom/vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import fixture from "../test/report.fixture.json";
import { App } from "./App";

function serve(body: unknown, ok = true) {
  vi.stubGlobal(
    "fetch",
    vi.fn(() => Promise.resolve({ ok, status: ok ? 200 : 500, json: () => Promise.resolve(body) })),
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("console", () => {
  it("shows a loading state, then the attack board with every attack held by the identity plane", async () => {
    serve(fixture);
    render(<App />);
    expect(screen.getByRole("status", { name: "Loading the report" })).toBeInTheDocument();
    const board = await screen.findByRole("region", { name: "Known attacks, one message each" });
    const kinds = Object.keys(fixture.dev.designs.platform.attacks).length;
    expect(within(board).getAllByLabelText("The identity plane: held")).toHaveLength(kinds);
    expect(within(board).getAllByText(/got in/).length).toBe(3);
    expect(within(board).getByRole("region", { name: "SAML sign-in" })).toBeInTheDocument();
  });

  it("compares access over the weeks and lists the safeguards", async () => {
    serve(fixture);
    render(<App />);
    const access = await screen.findByRole("region", { name: "Access over the weeks" });
    expect(within(access).getByRole("columnheader", { name: "The identity plane" })).toBeInTheDocument();
    const safe = screen.getByRole("region", { name: "What each safeguard is worth" });
    expect(within(safe).getByText(/A model read/)).toBeInTheDocument();
  });

  it("keeps the held-out tab closed until the held-out customers have run", async () => {
    serve(fixture);
    render(<App />);
    expect(await screen.findByRole("tab", { name: "Held-out customers, run once" })).toBeDisabled();
  });

  it("explains a failed load and loads again on request", async () => {
    serve({}, false);
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent("did not load");
    serve(fixture);
    await userEvent.click(screen.getByRole("button", { name: "Load again" }));
    expect(await screen.findByRole("heading", { name: "Known attacks, one message each" })).toBeInTheDocument();
  });

  it("says so when the report has no results for the identity plane", async () => {
    serve({ ...fixture, dev: { ...fixture.dev, designs: {} } });
    render(<App />);
    expect(await screen.findByText("This report has no results for the identity plane")).toBeInTheDocument();
  });

  it("refuses a file that is not a report", async () => {
    serve({ nope: true });
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent("not in the expected shape");
  });
});
