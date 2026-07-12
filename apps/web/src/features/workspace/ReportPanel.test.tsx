import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { generateIncidentReport } from "../../lib/api";
import { analysisFixture, incidentFixture } from "../../test/workspaceFixtures";
import { ReportPanel } from "./ReportPanel";

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    generateCaseReport: vi.fn(),
    generateIncidentReport: vi.fn(),
  };
});

const mockedGenerateReport = vi.mocked(generateIncidentReport);

describe("report workflow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedGenerateReport.mockResolvedValue({
      format: "markdown",
      filename: "incident.md",
      content: "# Incident report",
      created_at: "2026-01-01T00:04:00Z",
    });
  });

  it("generates a redacted report from selected deterministic evidence", async () => {
    const onReport = vi.fn();
    render(
      <ReportPanel
        result={analysisFixture}
        selectedIncident={incidentFixture}
        assistantResponse={null}
        reportFormat="markdown"
        report={null}
        onReport={onReport}
        onReportFormatChange={vi.fn()}
      />,
    );

    fireEvent.click(screen.getByRole("checkbox", { name: /redact ips/i }));
    fireEvent.click(screen.getByRole("button", { name: /generate report/i }));

    await waitFor(() => expect(onReport).toHaveBeenCalled());
    expect(mockedGenerateReport).toHaveBeenCalledWith(
      expect.objectContaining({
        incident: incidentFixture,
        findings: analysisFixture.findings,
        evidence: analysisFixture.evidence,
        redaction: expect.objectContaining({ enabled: true }),
      }),
    );
  });

  it("shows a report-generation error without retaining a stale report", async () => {
    mockedGenerateReport.mockRejectedValue(new Error("Report service unavailable"));
    const onReport = vi.fn();
    render(
      <ReportPanel
        result={analysisFixture}
        selectedIncident={incidentFixture}
        assistantResponse={null}
        reportFormat="markdown"
        report={null}
        onReport={onReport}
        onReportFormatChange={vi.fn()}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /generate report/i }));

    expect(await screen.findByText("Report service unavailable")).toBeInTheDocument();
    expect(onReport).toHaveBeenCalledWith(null);
  });
});
