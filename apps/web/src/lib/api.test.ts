import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  analyzeCaseBundle,
  analyzeDemo,
  analyzePublicDemo,
  analyzePublicSample,
  analyzeRealLabCase,
  analyzeSample,
  analyzeUpload,
  createIncidentNote,
  explainIncident,
  generateCaseReport,
  generateIncidentReport,
  generatePublicCaseReport,
  generatePublicIncidentReport,
  getAssistantSettings,
  getAssistantStatus,
  getAuthStatus,
  getPublicDemoStatus,
  getRuleLibrary,
  listIncidentNotes,
  liveFileWebSocketUrl,
  liveInterfaceWebSocketUrl,
  persistLiveSnapshot,
  previewAssistantPrompt,
  updateAssistantSettings,
  type LiveSnapshot,
} from "./api";
import {
  analysisFixture,
  evidenceFixture,
  findingFixture,
  incidentFixture,
} from "../test/workspaceFixtures";


const fetchMock = vi.fn();

function response(payload: unknown, ok = true) {
  return {
    ok,
    json: vi.fn().mockResolvedValue(payload),
  } as unknown as Response;
}

const assistantSettings = {
  ai_enabled: true,
  default_model: "qwen3:8b",
  show_prompt_preview: true,
  max_evidence_lines: 20,
  max_evidence_chars: 4000,
};

const liveSnapshot: LiveSnapshot = {
  message_type: "snapshot",
  source_id: "live-source",
  status: "active",
  parser: "linux_auth",
  raw_line_count: 1,
  parsed_event_count: 1,
  finding_count: 1,
  incident_count: 1,
  source_error: null,
  latest_line_number: 1,
  latest_event: null,
  events: [],
  evidence: [evidenceFixture],
  findings: [findingFixture],
  incidents: [incidentFixture],
  live_retention: {
    raw_line_capacity: 100,
    event_capacity: 100,
    total_raw_lines: 1,
    total_parsed_events: 1,
    retained_raw_lines: 1,
    retained_parsed_events: 1,
    dropped_raw_lines: 0,
    dropped_parsed_events: 0,
  },
  live_snapshot_attestation: "signed-snapshot",
};

describe("browser API boundary", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("uses the generated contract across read and mutation endpoints", async () => {
    fetchMock.mockResolvedValue(response({}));
    const upload = new File(["event"], "event.log", { type: "text/plain" });

    await getAuthStatus();
    await getAssistantStatus();
    await getAssistantSettings();
    await updateAssistantSettings(assistantSettings);
    await previewAssistantPrompt({
      incident: incidentFixture,
      findings: [findingFixture],
      evidence: [evidenceFixture],
    });
    await getRuleLibrary();
    await analyzeUpload(upload);
    await analyzeCaseBundle([upload]);
    await analyzeRealLabCase();
    await analyzeDemo();
    await analyzeSample("auth-ssh");
    await persistLiveSnapshot(liveSnapshot);
    await listIncidentNotes("analysis/id", "incident/id");
    await createIncidentNote({
      analysis_id: "analysis/id",
      incident_id: "incident/id",
      body: "Escalate",
      note_type: "decision",
    });
    await explainIncident({
      incident: incidentFixture,
      findings: [findingFixture],
      evidence: [evidenceFixture],
    });
    await generateIncidentReport({
      incident: incidentFixture,
      findings: [findingFixture],
      evidence: [evidenceFixture],
    });
    await generateCaseReport({ analysis: analysisFixture });

    expect(fetchMock).toHaveBeenCalledTimes(17);
    expect(fetchMock).toHaveBeenCalledWith("http://localhost:8000/auth/status");
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/assistant/settings",
      expect.objectContaining({ method: "PUT" }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/analyze/upload",
      expect.objectContaining({ method: "POST", body: expect.any(FormData) }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/analyze/case-bundle",
      expect.objectContaining({ method: "POST", body: expect.any(FormData) }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/notes/incidents/incident%2Fid?analysis_id=analysis%2Fid",
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/reports/incident?format=markdown",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("builds encoded secure and insecure live WebSocket URLs", () => {
    expect(liveFileWebSocketUrl("/var/log/auth log", true)).toBe(
      "ws://localhost:8000/api/live/file?path=%2Fvar%2Flog%2Fauth+log&start_at_end=true",
    );
    expect(liveInterfaceWebSocketUrl("eth 0", "tcp port 443")).toBe(
      "ws://localhost:8000/api/live/interface?interface=eth+0&capture_filter=tcp+port+443",
    );
  });

  it("uses only stateless public-demo endpoints for public analysis and reports", async () => {
    fetchMock.mockResolvedValue(response({}));
    const upload = new File(["event"], "event.log", { type: "text/plain" });

    await getPublicDemoStatus();
    await analyzePublicDemo(upload);
    await analyzePublicSample("auth-ssh-compromise");
    await generatePublicIncidentReport({
      incident: incidentFixture,
      findings: [findingFixture],
      evidence: [evidenceFixture],
    });
    await generatePublicCaseReport({ analysis: analysisFixture });

    expect(fetchMock).toHaveBeenCalledTimes(5);
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/public-demo/status",
      { cache: "no-store" },
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/public-demo/analyze",
      expect.objectContaining({
        method: "POST",
        cache: "no-store",
        body: JSON.stringify({ filename: "event.log", text: "event" }),
      }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/public-demo/report/incident",
      expect.objectContaining({ method: "POST", cache: "no-store" }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/public-demo/report/case",
      expect.objectContaining({ method: "POST", cache: "no-store" }),
    );
  });

  it("returns server detail and falls back when an error body is invalid", async () => {
    fetchMock.mockResolvedValueOnce(response({ detail: "Access denied" }, false));
    await expect(getAuthStatus()).rejects.toThrow("Access denied");

    fetchMock.mockResolvedValueOnce({
      ok: false,
      json: vi.fn().mockRejectedValue(new Error("invalid JSON")),
    } as unknown as Response);
    await expect(analyzeDemo()).rejects.toThrow("Demo analysis failed");
  });
});
