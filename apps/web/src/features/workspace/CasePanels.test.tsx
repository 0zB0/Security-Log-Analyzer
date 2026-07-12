import { fireEvent, render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";

import type { AnalysisResult } from "../../lib/api";
import { analysisFixture } from "../../test/workspaceFixtures";
import { CaseOverview } from "./CasePanels";


const caseResult: AnalysisResult = {
  ...analysisFixture,
  parser: "case_bundle",
  sources: [
    {
      filename: "suricata.jsonl",
      source_id: "suricata-source",
      parser: "suricata_eve",
      raw_line_count: 1,
      parsed_event_count: 1,
      finding_count: 1,
      incident_count: 1,
      content_sha256: "a".repeat(64),
    },
    {
      filename: "zeek-conn.log",
      source_id: "zeek-source",
      parser: "zeek_conn",
      raw_line_count: 1,
      parsed_event_count: 1,
      finding_count: 0,
      incident_count: 0,
      content_sha256: "b".repeat(64),
    },
  ],
  evidence: [
    {
      id: "raw-suricata",
      line_number: 1,
      raw_text: "suricata alert to 10.0.0.9:443",
      content_hash: "c".repeat(64),
    },
    {
      id: "raw-zeek",
      line_number: 1,
      raw_text: "zeek connection to 10.0.0.9:443",
      content_hash: "d".repeat(64),
    },
  ],
  events: [
    {
      id: "event-suricata",
      source_id: "suricata-source",
      raw_line_id: "raw-suricata",
      event_time: "2026-01-01T00:00:00Z",
      event_type: "alert",
      host: "sensor-1",
      service: "suricata",
      source_ip: "198.51.100.10",
      username: null,
      message: "suricata alert",
      normalized_fields: { destination_ip: "10.0.0.9", destination_port: 443 },
    },
    {
      id: "event-zeek",
      source_id: "zeek-source",
      raw_line_id: "raw-zeek",
      event_time: "2026-01-01T00:00:01Z",
      event_type: "network_connection",
      host: "sensor-1",
      service: "zeek",
      source_ip: "198.51.100.10",
      username: null,
      message: "zeek connection",
      normalized_fields: { destination_ip: "10.0.0.9", destination_port: 443 },
    },
  ],
  cross_source_links: [
    {
      id: "link-1",
      link_type: "flow_match",
      source_event_id: "event-suricata",
      target_event_id: "event-zeek",
      source_raw_line_id: "raw-suricata",
      target_raw_line_id: "raw-zeek",
      source_label: "suricata.jsonl",
      target_label: "zeek-conn.log",
      source_event_type: "alert",
      target_event_type: "network_connection",
      event_time: "2026-01-01T00:00:00Z",
      source_ip: "198.51.100.10",
      destination_ip: "10.0.0.9",
      destination_port: "443",
      match_value: "198.51.100.10|10.0.0.9|443",
      summary: "Suricata alert corroborated by Zeek flow",
      confidence: "high",
    },
  ],
  case_quality: {
    strongest_incident_id: analysisFixture.incidents[0].id,
    strongest_incident_title: analysisFixture.incidents[0].title,
    strongest_incident_score: 91,
    sequence_backed_incident_count: 1,
    cross_source_corroborated_incident_count: 1,
    total_cross_source_links: 1,
    top_scoring_reason: "Sequence and cross-source support",
  },
};

describe("case investigation", () => {
  it("renders the empty case boundary", () => {
    render(<CaseOverview result={null} />);
    expect(screen.getByText("No case loaded.")).toBeInTheDocument();
  });

  it("pivots from source summary to cross-source raw evidence", async () => {
    const { container } = render(<CaseOverview result={caseResult} />);

    expect(screen.getByRole("heading", { name: "Case quality" })).toBeInTheDocument();
    expect(screen.getByText("Sequence and cross-source support")).toBeInTheDocument();
    expect(
      screen.getAllByText("Suricata alert corroborated by Zeek flow").length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("suricata alert to 10.0.0.9:443")).toBeInTheDocument();
    expect(screen.getByText("zeek connection to 10.0.0.9:443")).toBeInTheDocument();

    const sourceButton = container.querySelector<HTMLButtonElement>(".source-row");
    expect(sourceButton).not.toBeNull();
    fireEvent.click(sourceButton as HTMLButtonElement);
    expect(screen.getByText("1 visible joins across Zeek and Suricata.")).toBeInTheDocument();
    expect((await axe(container)).violations).toHaveLength(0);
  });
});
