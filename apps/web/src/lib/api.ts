const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? (import.meta.env.DEV ? "http://localhost:8000" : "");

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";

export interface MitreMapping {
  tactic: string | null;
  technique_id: string | null;
  technique_name: string | null;
  note: string | null;
}

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  summary: string;
  reason: string;
  mitre: MitreMapping;
  first_seen: string;
  last_seen: string;
  event_count: number;
  evidence_line_ids: string[];
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: "active" | "investigating" | "closed" | "false_positive";
  summary: string;
  first_seen: string;
  last_seen: string;
  score: number;
  score_breakdown: Record<string, number>;
  score_rationale: string[];
  finding_ids: string[];
  entities: string[];
  timeline: string[];
  mitre_techniques: string[];
}

export interface Entity {
  id: string;
  analysis_id: string | null;
  entity_type: "ip" | "user" | "host" | "service" | "path" | "domain" | "url" | "container";
  value: string;
  first_seen: string | null;
  last_seen: string | null;
  risk_score: number;
  event_count: number;
  source_ids: string[];
  finding_ids: string[];
  incident_ids: string[];
}

export interface EvidenceLine {
  id: string;
  line_number: number;
  raw_text: string;
  content_hash: string;
}

export interface SourceSummary {
  filename: string;
  source_id: string;
  parser: string;
  raw_line_count: number;
  parsed_event_count: number;
  finding_count: number;
  incident_count: number;
  content_sha256: string;
}

export interface CrossSourceLink {
  id: string;
  link_type: string;
  source_event_id: string;
  target_event_id: string;
  source_raw_line_id: string;
  target_raw_line_id: string;
  source_label: string;
  target_label: string;
  source_event_type: string;
  target_event_type: string;
  event_time: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  destination_port: string | null;
  match_value: string | null;
  summary: string;
  confidence: string;
}

export interface CaseQualitySummary {
  strongest_incident_id: string | null;
  strongest_incident_title: string | null;
  strongest_incident_score: number;
  sequence_backed_incident_count: number;
  cross_source_corroborated_incident_count: number;
  total_cross_source_links: number;
  top_scoring_reason: string | null;
}

export interface ParsedEvent {
  id: string;
  source_id: string;
  raw_line_id: string;
  event_time: string | null;
  event_type: string;
  host: string | null;
  service: string | null;
  source_ip: string | null;
  username: string | null;
  message: string;
  normalized_fields: Record<string, unknown>;
}

export interface AnalysisResult {
  analysis_id: string | null;
  source_id: string;
  parser: string;
  raw_line_count: number;
  parsed_event_count: number;
  finding_count: number;
  incident_count: number;
  events: ParsedEvent[];
  findings: Finding[];
  incidents: Incident[];
  entities: Entity[];
  evidence: EvidenceLine[];
  sources: SourceSummary[];
  cross_source_links: CrossSourceLink[];
  case_quality: CaseQualitySummary | null;
}

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
}

export interface AssistantResponse {
  provider: string;
  model: string;
  mode: string;
  prompt: string;
  summary: string;
  key_points: string[];
  recommended_next_steps: string[];
  evidence_references: number[];
  guardrails: string[];
}

export interface AssistantStatus {
  enabled: boolean;
  provider: string;
  url: string;
  model: string | null;
  available: boolean;
  installed_models: string[];
  error: string | null;
}

export interface AssistantSettings {
  ai_enabled: boolean;
  default_model: string;
  show_prompt_preview: boolean;
  max_evidence_lines: number;
  max_evidence_chars: number;
}

export interface PromptBuildResult {
  prompt: string;
  evidence_line_count: number;
  truncated: boolean;
}

export interface AuthStatus {
  authenticated: boolean;
  email: string | null;
  allowed: boolean;
  role: "viewer" | "analyst" | "admin" | null;
  auth_mode: "disabled" | "azure_easy_auth" | string;
  allowlist_enabled: boolean;
  local_admin: boolean;
}

export interface AnalystNote {
  id: string;
  analysis_id: string;
  incident_id: string;
  body: string;
  note_type: "observation" | "decision" | "follow_up" | "false_positive";
  author: string;
  created_at: string;
  updated_at: string;
}

export interface ReportResponse {
  format: "markdown" | "html" | "pdf";
  filename: string;
  content: string;
  created_at: string;
}

export interface RuleLibraryItem {
  id: string;
  title: string;
  category: string;
  description: string;
  danger_summary: string;
  severity: Severity;
  confidence: Confidence;
  log_types: string[];
  mitre_tactic: string | null;
  mitre_technique_id: string | null;
  mitre_technique_name: string | null;
  look_for: string[];
  false_positives: string[];
  recommendations: string[];
}

export interface RuleLibraryResponse {
  rule_count: number;
  categories: string[];
  rules: RuleLibraryItem[];
}

export interface ReportRedactionOptions {
  enabled: boolean;
  mask_ips?: boolean;
  mask_users?: boolean;
  mask_hosts?: boolean;
}

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
