import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { axe } from "vitest-axe";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { persistLiveSnapshot, type LiveSnapshot } from "../../lib/api";
import { analysisFixture, evidenceFixture } from "../../test/workspaceFixtures";
import { LiveMonitor } from "./LiveMonitor";


vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return { ...actual, persistLiveSnapshot: vi.fn() };
});

const mockedPersistLiveSnapshot = vi.mocked(persistLiveSnapshot);

const snapshot: LiveSnapshot = {
  message_type: "snapshot",
  source_id: "live-source",
  status: "active",
  parser: "linux_auth",
  raw_line_count: 6,
  parsed_event_count: 5,
  finding_count: 0,
  incident_count: 0,
  source_error: null,
  latest_line_number: 6,
  latest_event: null,
  events: [],
  evidence: [evidenceFixture],
  findings: [],
  incidents: [],
  live_retention: {
    raw_line_capacity: 5,
    event_capacity: 4,
    total_raw_lines: 6,
    total_parsed_events: 5,
    retained_raw_lines: 5,
    retained_parsed_events: 4,
    dropped_raw_lines: 1,
    dropped_parsed_events: 1,
  },
  live_snapshot_attestation: "signed-snapshot",
};

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];

  readonly url: string;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  send = vi.fn();

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  close() {
    this.onclose?.();
  }
}

describe("bounded live monitor", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    FakeWebSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeWebSocket);
  });

  it("surfaces a rejected attestation and recovers on a valid retry", async () => {
    mockedPersistLiveSnapshot
      .mockRejectedValueOnce(new Error("Live snapshot attestation is invalid"))
      .mockResolvedValueOnce(analysisFixture);
    const onError = vi.fn();
    const onSaved = vi.fn();
    render(
      <LiveMonitor
        initialSnapshot={snapshot}
        onSnapshot={vi.fn()}
        onSaved={onSaved}
        onError={onError}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(onError).toHaveBeenCalledWith("Live snapshot attestation is invalid"),
    );

    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith(analysisFixture));
    expect(mockedPersistLiveSnapshot).toHaveBeenCalledTimes(2);
  });

  it("connects, displays bounded retention, and sends source controls", async () => {
    const onSnapshot = vi.fn();
    const onError = vi.fn();
    const { container } = render(
      <LiveMonitor
        initialSnapshot={null}
        onSnapshot={onSnapshot}
        onSaved={vi.fn()}
        onError={onError}
      />,
    );

    fireEvent.click(screen.getByRole("checkbox", { name: /only new lines/i }));
    fireEvent.click(screen.getByRole("button", { name: /^start$/i }));
    const socket = FakeWebSocket.instances[0];
    expect(socket.url).toContain("start_at_end=true");

    act(() => socket.onopen?.());
    act(() => socket.onmessage?.({ data: JSON.stringify(snapshot) }));
    expect(screen.getByText("5/6 retained lines")).toBeInTheDocument();
    expect(screen.getByText("1 dropped lines")).toBeInTheDocument();
    expect(onSnapshot).toHaveBeenCalledWith(snapshot);

    fireEvent.click(screen.getByRole("button", { name: /^pause$/i }));
    expect(socket.send).toHaveBeenCalledWith(JSON.stringify({ action: "pause" }));
    fireEvent.click(screen.getByRole("button", { name: /^stop$/i }));
    expect(screen.getByText("idle")).toBeInTheDocument();
    expect((await axe(container)).violations).toHaveLength(0);
  });
});
