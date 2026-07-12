import { describe, expect, it } from "vitest";

import type { AnalysisResult, CrossSourceLink, Finding, ParsedEvent } from "../../lib/api";
import {
  base64ToArrayBuffer,
  buildCaseMetrics,
  buildCaseTimeline,
  buildMitreGroups,
  formatScoreComponent,
  formatTime,
  filterFindingsByQuery,
  groupCrossSourceLinks,
  linkGroupLabel,
  shortId,
  stringValue,
} from "./workspaceSelectors";

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  id: "finding-1",
  rule_id: "rule-b",
  title: "Suspicious activity",
  severity: "medium",
  confidence: "high",
  summary: "summary",
  reason: "reason",
  mitre: {
    tactic: "Discovery",
    technique_id: "T1046",
    technique_name: "Network Service Discovery",
    note: null,
  },
  first_seen: "2026-01-01T00:00:00Z",
  last_seen: "2026-01-01T00:01:00Z",
  event_count: 1,
  evidence_line_ids: ["evidence-1"],
  ...overrides,
});

const event = (overrides: Partial<ParsedEvent> = {}): ParsedEvent => ({
  id: "event-1",
  source_id: "source-a",
  raw_line_id: "evidence-1",
  event_time: "2026-01-01T00:00:00Z",
  event_type: "connection",
  host: null,
  service: null,
  source_ip: "192.0.2.1",
  username: null,
  message: "connection observed",
  normalized_fields: {},
  ...overrides,
});

const link = (overrides: Partial<CrossSourceLink> = {}): CrossSourceLink => ({
  id: "link-1",
  link_type: "flow_match",
  source_event_id: "event-1",
  target_event_id: "event-2",
  source_raw_line_id: "evidence-1",
  target_raw_line_id: "evidence-2",
  source_label: "zeek.log",
  target_label: "suricata.jsonl",
  source_event_type: "connection",
  target_event_type: "alert",
  event_time: "2026-01-01T00:00:01Z",
  source_ip: "192.0.2.1",
  destination_ip: "198.51.100.2",
  destination_port: "443",
  match_value: "flow",
  summary: "independent sources agree",
  confidence: "high",
  ...overrides,
});

const analysis = (overrides: Partial<AnalysisResult> = {}): AnalysisResult => ({
  analysis_id: "analysis-1",
  source_id: "case-1",
  parser: "case_bundle",
  raw_line_count: 4,
  parsed_event_count: 3,
  finding_count: 2,
  incident_count: 1,
  events: [event()],
  findings: [finding()],
  incidents: [],
  entities: [],
  evidence: [],
  sources: [
    {
      filename: "zeek.log",
      source_id: "source-a",
      parser: "zeek",
      raw_line_count: 2,
      parsed_event_count: 2,
      finding_count: 1,
      incident_count: 1,
      content_sha256: "a".repeat(64),
    },
    {
      filename: "suricata.jsonl",
      source_id: "source-b",
      parser: "suricata",
      raw_line_count: 2,
      parsed_event_count: 1,
      finding_count: 1,
      incident_count: 1,
      content_sha256: "short",
    },
  ],
  cross_source_links: [link()],
  case_quality: null,
  ...overrides,
});

describe("workspace selectors", () => {
  it("filters findings across analyst-visible rule, rationale, severity, and MITRE text", () => {
    const findings = [
      finding(),
      finding({
        id: "finding-2",
        rule_id: "ssh-bruteforce-001",
        title: "SSH brute force",
        severity: "high",
        mitre: {
          tactic: "Credential Access",
          technique_id: "T1110.001",
          technique_name: "Password Guessing",
          note: null,
        },
      }),
    ];

    expect(filterFindingsByQuery(findings, "  t1110  ")).toEqual([findings[1]]);
    expect(filterFindingsByQuery(findings, "MEDIUM")).toEqual([findings[0]]);
    expect(filterFindingsByQuery(findings, "no match")).toEqual([]);
    expect(filterFindingsByQuery(findings, " ")).toBe(findings);
  });

  it("groups MITRE findings and retains strongest severity and unique evidence", () => {
    const groups = buildMitreGroups([
      finding(),
      finding({ id: "finding-2", rule_id: "rule-a", severity: "critical" }),
      finding({
        id: "finding-3",
        mitre: { tactic: null, technique_id: null, technique_name: null, note: null },
      }),
    ]);

    expect(groups.map((group) => group.tactic)).toEqual(["Discovery", "Unmapped"]);
    expect(groups[0].findingCount).toBe(2);
    expect(groups[0].techniques[0]).toMatchObject({
      maxSeverity: "critical",
      ruleIds: ["rule-a", "rule-b"],
      evidenceCount: 1,
    });
  });

  it("groups cross-source links by frequency and labels known types", () => {
    const groups = groupCrossSourceLinks([
      link(),
      link({ id: "link-2", link_type: "dns_query_match" }),
      link({ id: "link-3", link_type: "dns_query_match" }),
    ]);

    expect(groups.map((group) => [group.type, group.links.length])).toEqual([
      ["dns_query_match", 2],
      ["flow_match", 1],
    ]);
    expect(linkGroupLabel("http_path_match")).toBe("HTTP path matches");
    expect(linkGroupLabel("dns_query_match")).toBe("DNS query matches");
    expect(linkGroupLabel("flow_match")).toBe("Flow matches");
    expect(linkGroupLabel("custom")).toBe("custom");
  });

  it("builds deterministic case metrics including zero-denominator states", () => {
    expect(buildCaseMetrics(analysis())).toEqual([
      { label: "Sources", value: "2" },
      { label: "Parsers", value: "2" },
      { label: "Parsed", value: "75%" },
      { label: "Findings", value: "2" },
      { label: "Incidents", value: "1" },
      { label: "Links", value: "1" },
      { label: "Hashes", value: "50%" },
    ]);
    expect(
      buildCaseMetrics(analysis({ raw_line_count: 0, parsed_event_count: 0, sources: [] })),
    ).toEqual(expect.arrayContaining([{ label: "Parsed", value: "0%" }, { label: "Hashes", value: "0%" }]));
  });

  it("sorts the merged case timeline and applies the selected source filter", () => {
    const result = analysis({
      events: [
        event({ id: "late", event_time: "2026-01-01T00:00:02Z" }),
        event({ id: "early", event_time: "2026-01-01T00:00:00Z" }),
        event({ id: "other", source_id: "source-b" }),
      ],
    });

    expect(buildCaseTimeline(result, "all").map((item) => item.id)).toEqual([
      "early",
      "other",
      "link-1",
      "late",
    ]);
    expect(buildCaseTimeline(result, "source-a").map((item) => item.id)).toEqual([
      "early",
      "link-1",
      "late",
    ]);
  });

  it("normalizes labels, identifiers, nullable values, base64, and invalid times", () => {
    expect(formatScoreComponent("cross_source_corroboration")).toBe("Cross Source Corroboration");
    expect(shortId("a".repeat(25))).toBe(`${"a".repeat(24)}...`);
    expect(shortId("short")).toBe("short");
    expect(stringValue(null)).toBeNull();
    expect(stringValue(undefined)).toBeNull();
    expect(stringValue("")).toBeNull();
    expect(stringValue(42)).toBe("42");
    expect(Array.from(new Uint8Array(base64ToArrayBuffer("VHJhY2VIYXdr")))).toEqual(
      Array.from(new TextEncoder().encode("TraceHawk")),
    );
    expect(formatTime("not-a-time")).toBe("not-a-time");
  });
});
