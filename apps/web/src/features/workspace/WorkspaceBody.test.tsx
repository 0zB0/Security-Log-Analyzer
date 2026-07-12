import { render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";

import { MetricGrid, snapshotToAnalysisResult } from "./WorkspaceBody";

describe("workspace public components", () => {
  it("converts live snapshots without inventing persisted case data", () => {
    const result = snapshotToAnalysisResult({
      message_type: "snapshot",
      source_id: "live-1",
      status: "active",
      parser: null,
      raw_line_count: 3,
      parsed_event_count: 2,
      finding_count: 1,
      incident_count: 1,
      source_error: null,
      latest_line_number: 3,
      latest_event: null,
      events: [],
      evidence: [],
      findings: [],
      incidents: [],
      live_retention: {
        raw_line_capacity: 100,
        event_capacity: 100,
        total_raw_lines: 3,
        total_parsed_events: 2,
        retained_raw_lines: 3,
        retained_parsed_events: 2,
        dropped_raw_lines: 0,
        dropped_parsed_events: 0,
      },
      live_snapshot_attestation: "attestation-proof",
    });

    expect(result).toMatchObject({
      source_id: "live-1",
      parser: "detecting",
      analysis_id: null,
      entities: [],
      sources: [],
      cross_source_links: [],
      case_quality: null,
      live_snapshot_attestation: "attestation-proof",
      live_retention: {
        retained_raw_lines: 3,
        dropped_raw_lines: 0,
      },
    });
  });

  it("renders an accessible metric summary for idle and analyzed states", async () => {
    const { container, rerender } = render(<MetricGrid result={null} isAnalyzing={false} />);
    expect(screen.getByText("Waiting")).toBeInTheDocument();
    expect((await axe(container)).violations).toHaveLength(0);

    rerender(
      <MetricGrid
        isAnalyzing={false}
        result={{
          analysis_id: "analysis-1",
          source_id: "source-1",
          parser: "zeek",
          raw_line_count: 20,
          parsed_event_count: 18,
          finding_count: 2,
          incident_count: 1,
          events: [],
          findings: [],
          incidents: [],
          entities: [],
          evidence: [],
          sources: [],
          cross_source_links: [],
          case_quality: null,
        }}
      />,
    );
    expect(screen.getByText("zeek")).toBeInTheDocument();
    expect(screen.getByText("20")).toBeInTheDocument();
  });
});
