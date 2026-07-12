import type {
  AnalysisResult as ApiAnalysisResult,
  AnalystNote as ApiAnalystNote,
  AssistantResponse as ApiAssistantResponse,
  AssistantSettings as ApiAssistantSettings,
  CaseQualitySummary as ApiCaseQualitySummary,
  CrossSourceLink as ApiCrossSourceLink,
  Entity as ApiEntity,
  EvidenceIntegritySummary as ApiEvidenceIntegritySummary,
  EvidenceLine as ApiEvidenceLine,
  Finding as ApiFinding,
  Incident as ApiIncident,
  LiveRetentionSummary as ApiLiveRetentionSummary,
  LocalLLMStatus as ApiLocalLLMStatus,
  MitreMapping as ApiMitreMapping,
  ParsedEvent as ApiParsedEvent,
  PromptBuildResult as ApiPromptBuildResult,
  ReportRedactionOptions as ApiReportRedactionOptions,
  ReportResponse as ApiReportResponse,
  RuleCorrelationMetadata as ApiRuleCorrelationMetadata,
  RuleLibraryItem as ApiRuleLibraryItem,
  RuleLibraryResponse as ApiRuleLibraryResponse,
  SourceSummary as ApiSourceSummary,
} from "../generated/api-schema";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? (import.meta.env.DEV ? "http://localhost:8000" : "");

export type Severity = ApiFinding["severity"];
export type Confidence = ApiFinding["confidence"];
export type MitreMapping = Required<ApiMitreMapping>;
export type Finding = Required<ApiFinding> & { mitre: MitreMapping };
export type Incident = Required<ApiIncident>;
export type Entity = Required<ApiEntity>;
export type EvidenceLine = ApiEvidenceLine;
export type SourceSummary = ApiSourceSummary;
export type CrossSourceLink = Required<ApiCrossSourceLink>;
export type CaseQualitySummary = Required<ApiCaseQualitySummary>;
export type LiveRetentionSummary = ApiLiveRetentionSummary;
export type EvidenceIntegritySummary = Required<ApiEvidenceIntegritySummary> & {
  live_retention: LiveRetentionSummary | null;
};
export type ParsedEvent = Required<ApiParsedEvent>;

export type AnalysisResult = Omit<
  Required<ApiAnalysisResult>,
  | "events"
  | "findings"
  | "incidents"
  | "entities"
  | "evidence"
  | "sources"
  | "cross_source_links"
  | "case_quality"
  | "evidence_integrity"
  | "live_retention"
  | "live_snapshot_attestation"
> & {
  events: ParsedEvent[];
  findings: Finding[];
  incidents: Incident[];
  entities: Entity[];
  evidence: EvidenceLine[];
  sources: SourceSummary[];
  cross_source_links: CrossSourceLink[];
  case_quality: CaseQualitySummary | null;
  evidence_integrity?: EvidenceIntegritySummary | null;
  live_retention?: LiveRetentionSummary | null;
  live_snapshot_attestation?: string | null;
};

export interface LiveSnapshot {
  message_type: "snapshot";
  source_id: string;
  status: "active" | "paused" | "error";
  parser: string | null;
  raw_line_count: number;
  parsed_event_count: number;
  finding_count: number;
  incident_count: number;
  source_error: string | null;
  latest_line_number: number | null;
  latest_event: ParsedEvent | null;
  events: ParsedEvent[];
  evidence: EvidenceLine[];
  findings: Finding[];
  incidents: Incident[];
  live_retention: LiveRetentionSummary;
  live_snapshot_attestation: string | null;
}

export type AssistantResponse = Required<ApiAssistantResponse>;
export type AssistantStatus = Required<ApiLocalLLMStatus>;
export type AssistantSettings = Required<ApiAssistantSettings>;
export type PromptBuildResult = Required<ApiPromptBuildResult>;

export interface AuthStatus {
  authenticated: boolean;
  email: string | null;
  allowed: boolean;
  role: "viewer" | "analyst" | "admin" | null;
  auth_mode: "disabled" | "azure_easy_auth" | string;
  allowlist_enabled: boolean;
  local_admin: boolean;
}

export type AnalystNote = Required<ApiAnalystNote>;
export type ReportResponse = Required<ApiReportResponse> & {
  format: "markdown" | "html" | "pdf";
};
export type RuleCorrelationMetadata = Required<ApiRuleCorrelationMetadata>;
export type RuleLibraryItem = Required<Omit<ApiRuleLibraryItem, "correlation">> & {
  correlation: RuleCorrelationMetadata;
};
export type RuleLibraryResponse = Omit<ApiRuleLibraryResponse, "rules"> & {
  rules: RuleLibraryItem[];
};
export type ReportRedactionOptions = Omit<ApiReportRedactionOptions, "enabled"> & {
  enabled: boolean;
};

export async function getAuthStatus(): Promise<AuthStatus> {
  const response = await fetch(`${API_BASE_URL}/auth/status`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Auth status failed" }));
    throw new Error(error.detail ?? "Auth status failed");
  }

  return response.json();
}

export async function getAssistantStatus(): Promise<AssistantStatus> {
  const response = await fetch(`${API_BASE_URL}/api/assistant/status`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Assistant status failed" }));
    throw new Error(error.detail ?? "Assistant status failed");
  }

  return response.json();
}

export async function getAssistantSettings(): Promise<AssistantSettings> {
  const response = await fetch(`${API_BASE_URL}/api/assistant/settings`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Assistant settings failed" }));
    throw new Error(error.detail ?? "Assistant settings failed");
  }

  return response.json();
}

export async function updateAssistantSettings(settings: AssistantSettings): Promise<AssistantSettings> {
  const response = await fetch(`${API_BASE_URL}/api/assistant/settings`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(settings),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Assistant settings update failed" }));
    throw new Error(error.detail ?? "Assistant settings update failed");
  }

  return response.json();
}

export async function previewAssistantPrompt(payload: {
  incident: Incident;
  findings: Finding[];
  evidence: EvidenceLine[];
  question?: string;
  model?: string;
}): Promise<PromptBuildResult> {
  const response = await fetch(`${API_BASE_URL}/api/assistant/prompt-preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Prompt preview failed" }));
    throw new Error(error.detail ?? "Prompt preview failed");
  }

  return response.json();
}

export async function getRuleLibrary(): Promise<RuleLibraryResponse> {
  const response = await fetch(`${API_BASE_URL}/api/rules/library`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Rule library failed" }));
    throw new Error(error.detail ?? "Rule library failed");
  }

  return response.json();
}

export async function analyzeUpload(file: File): Promise<AnalysisResult> {
  const form = new FormData();
  form.append("file", file);

  const response = await fetch(`${API_BASE_URL}/api/analyze/upload`, {
    method: "POST",
    body: form,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Upload failed" }));
    throw new Error(error.detail ?? "Upload failed");
  }

  return response.json();
}

export async function analyzeCaseBundle(files: FileList | File[]): Promise<AnalysisResult> {
  const form = new FormData();
  Array.from(files).forEach((file) => form.append("files", file));

  const response = await fetch(`${API_BASE_URL}/api/analyze/case-bundle`, {
    method: "POST",
    body: form,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Case bundle analysis failed" }));
    throw new Error(error.detail ?? "Case bundle analysis failed");
  }

  return response.json();
}

export async function analyzeRealLabCase(): Promise<AnalysisResult> {
  const response = await fetch(`${API_BASE_URL}/api/analyze/case-sample/real-lab`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Real lab case analysis failed" }));
    throw new Error(error.detail ?? "Real lab case analysis failed");
  }

  return response.json();
}

export async function analyzeDemo(): Promise<AnalysisResult> {
  const response = await fetch(`${API_BASE_URL}/api/analyze/demo`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Demo analysis failed" }));
    throw new Error(error.detail ?? "Demo analysis failed");
  }

  return response.json();
}

export async function analyzeSample(sampleId: string): Promise<AnalysisResult> {
  const response = await fetch(`${API_BASE_URL}/api/analyze/sample/${encodeURIComponent(sampleId)}`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Sample analysis failed" }));
    throw new Error(error.detail ?? "Sample analysis failed");
  }

  return response.json();
}

export async function persistLiveSnapshot(snapshot: LiveSnapshot): Promise<AnalysisResult> {
  const response = await fetch(`${API_BASE_URL}/api/analyze/live-snapshot`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(snapshotToAnalysisResult(snapshot)),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Live snapshot save failed" }));
    throw new Error(error.detail ?? "Live snapshot save failed");
  }

  return response.json();
}

export async function listIncidentNotes(analysisId: string, incidentId: string): Promise<AnalystNote[]> {
  const response = await fetch(
    `${API_BASE_URL}/api/notes/incidents/${encodeURIComponent(incidentId)}?analysis_id=${encodeURIComponent(analysisId)}`
  );

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Note lookup failed" }));
    throw new Error(error.detail ?? "Note lookup failed");
  }

  return response.json();
}

export async function createIncidentNote(payload: {
  analysis_id: string;
  incident_id: string;
  body: string;
  note_type: AnalystNote["note_type"];
}): Promise<AnalystNote> {
  const response = await fetch(`${API_BASE_URL}/api/notes/incidents/${encodeURIComponent(payload.incident_id)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      analysis_id: payload.analysis_id,
      body: payload.body,
      note_type: payload.note_type,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Note creation failed" }));
    throw new Error(error.detail ?? "Note creation failed");
  }

  return response.json();
}

export function liveFileWebSocketUrl(path: string, startAtEnd: boolean): string {
  const url = new URL(API_BASE_URL);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/api/live/file";
  url.searchParams.set("path", path);
  url.searchParams.set("start_at_end", String(startAtEnd));
  return url.toString();
}

export function liveInterfaceWebSocketUrl(interfaceName: string, captureFilter: string): string {
  const url = new URL(API_BASE_URL);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/api/live/interface";
  url.searchParams.set("interface", interfaceName);
  url.searchParams.set("capture_filter", captureFilter);
  return url.toString();
}

function snapshotToAnalysisResult(snapshot: LiveSnapshot): AnalysisResult {
  return {
    analysis_id: null,
    source_id: snapshot.source_id,
    parser: snapshot.parser ?? "detecting",
    raw_line_count: snapshot.raw_line_count,
    parsed_event_count: snapshot.parsed_event_count,
    finding_count: snapshot.finding_count,
    incident_count: snapshot.incident_count,
    events: snapshot.events,
    findings: snapshot.findings,
    incidents: snapshot.incidents,
    entities: [],
    evidence: snapshot.evidence,
    sources: [],
    cross_source_links: [],
    case_quality: null,
    evidence_integrity: null,
    live_retention: snapshot.live_retention,
    live_snapshot_attestation: snapshot.live_snapshot_attestation,
  };
}

export async function explainIncident(payload: {
  incident: Incident;
  findings: Finding[];
  evidence: EvidenceLine[];
  question?: string;
  model?: string;
}): Promise<AssistantResponse> {
  const response = await fetch(`${API_BASE_URL}/api/assistant/explain`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Assistant request failed" }));
    throw new Error(error.detail ?? "Assistant request failed");
  }

  return response.json();
}

export async function generateIncidentReport(payload: {
  incident: Incident;
  findings: Finding[];
  evidence: EvidenceLine[];
  assistant_summary?: string;
  format?: "markdown" | "html" | "pdf";
  redaction?: ReportRedactionOptions;
}): Promise<ReportResponse> {
  const format = payload.format ?? "markdown";
  const response = await fetch(`${API_BASE_URL}/api/reports/incident?format=${format}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      incident: payload.incident,
      findings: payload.findings,
      evidence: payload.evidence,
      assistant_summary: payload.assistant_summary,
      redaction: payload.redaction,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Report generation failed" }));
    throw new Error(error.detail ?? "Report generation failed");
  }

  return response.json();
}

export async function generateCaseReport(payload: {
  analysis: AnalysisResult;
  assistant_summary?: string;
  format?: "markdown" | "pdf";
  redaction?: ReportRedactionOptions;
}): Promise<ReportResponse> {
  const format = payload.format ?? "markdown";
  const response = await fetch(`${API_BASE_URL}/api/reports/case?format=${format}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      analysis: payload.analysis,
      assistant_summary: payload.assistant_summary,
      redaction: payload.redaction,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Case report generation failed" }));
    throw new Error(error.detail ?? "Case report generation failed");
  }

  return response.json();
}
