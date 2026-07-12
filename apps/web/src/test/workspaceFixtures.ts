import type { AnalysisResult, EvidenceLine, Finding, Incident } from "../lib/api";

export const findingFixture: Finding = {
  id: "finding-1",
  rule_id: "ssh-bruteforce-001",
  title: "SSH brute-force activity",
  severity: "high",
  confidence: "high",
  summary: "Repeated failures were followed by a successful login.",
  reason: "Six failed logins from one source",
  mitre: {
    tactic: "Credential Access",
    technique_id: "T1110.001",
    technique_name: "Password Guessing",
    note: null,
  },
  first_seen: "2026-01-01T00:00:00Z",
  last_seen: "2026-01-01T00:01:00Z",
  event_count: 6,
  evidence_line_ids: ["evidence-1"],
};

export const incidentFixture: Incident = {
  id: "incident-1",
  title: "Possible SSH credential compromise",
  severity: "critical",
  status: "active",
  summary: "Correlated authentication findings require review.",
  first_seen: "2026-01-01T00:00:00Z",
  last_seen: "2026-01-01T00:02:00Z",
  score: 91,
  score_breakdown: { severity: 40, sequence_support: 25 },
  score_rationale: ["Critical finding", "Sequence-backed activity"],
  finding_ids: [findingFixture.id],
  entities: ["ip:198.51.100.10"],
  timeline: ["2026-01-01T00:00:00Z — failures", "2026-01-01T00:02:00Z — success"],
  mitre_techniques: ["T1110.001"],
};

export const evidenceFixture: EvidenceLine = {
  id: "evidence-1",
  line_number: 7,
  raw_text: "sshd[42]: Failed password for analyst from 198.51.100.10",
  content_hash: "a".repeat(64),
};

export const analysisFixture: AnalysisResult = {
  analysis_id: "analysis-1",
  source_id: "source-1",
  parser: "linux_auth",
  raw_line_count: 8,
  parsed_event_count: 8,
  finding_count: 1,
  incident_count: 1,
  events: [],
  findings: [findingFixture],
  incidents: [incidentFixture],
  entities: [],
  evidence: [evidenceFixture],
  sources: [],
  cross_source_links: [],
  case_quality: null,
};
