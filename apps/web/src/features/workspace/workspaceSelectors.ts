import type { AnalysisResult, Finding } from "../../lib/api";

export interface MitreGroup {
  tactic: string;
  findingCount: number;
  techniques: {
    techniqueId: string | null;
    techniqueName: string | null;
    maxSeverity: Finding["severity"];
    ruleIds: string[];
    findingIds: string[];
    evidenceCount: number;
  }[];
}

export interface CaseTimelineItem {
  id: string;
  timestamp: string | null;
  kind: "event" | "link";
  source: string;
  summary: string;
  detail: string;
}

export function filterFindingsByQuery(findings: Finding[], query: string): Finding[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return findings;
  }
  return findings.filter((finding) =>
    [
      finding.title,
      finding.rule_id,
      finding.summary,
      finding.reason,
      finding.severity,
      finding.confidence,
      finding.mitre.tactic,
      finding.mitre.technique_id,
      finding.mitre.technique_name,
    ]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(normalizedQuery)),
  );
}

export function buildMitreGroups(findings: Finding[]): MitreGroup[] {
  const tacticMap = new Map<
    string,
    Map<
      string,
      {
        techniqueId: string | null;
        techniqueName: string | null;
        maxSeverity: Finding["severity"];
        ruleIds: Set<string>;
        findingIds: string[];
        evidenceIds: Set<string>;
      }
    >
  >();
  for (const finding of findings) {
    const tactic = finding.mitre.tactic ?? "Unmapped";
    const techniqueKey = finding.mitre.technique_id ?? "unmapped";
    const techniques = tacticMap.get(tactic) ?? new Map();
    const current = techniques.get(techniqueKey) ?? {
      techniqueId: finding.mitre.technique_id,
      techniqueName: finding.mitre.technique_name,
      maxSeverity: finding.severity,
      ruleIds: new Set<string>(),
      findingIds: [],
      evidenceIds: new Set<string>(),
    };
    current.maxSeverity = higherSeverity(current.maxSeverity, finding.severity);
    current.ruleIds.add(finding.rule_id);
    current.findingIds.push(finding.id);
    finding.evidence_line_ids.forEach((id) => current.evidenceIds.add(id));
    techniques.set(techniqueKey, current);
    tacticMap.set(tactic, techniques);
  }
  return Array.from(tacticMap.entries())
    .map(([tactic, techniques]) => ({
      tactic,
      findingCount: Array.from(techniques.values()).reduce(
        (total, item) => total + item.findingIds.length,
        0,
      ),
      techniques: Array.from(techniques.values()).map((item) => ({
        techniqueId: item.techniqueId,
        techniqueName: item.techniqueName,
        maxSeverity: item.maxSeverity,
        ruleIds: Array.from(item.ruleIds).sort(),
        findingIds: item.findingIds,
        evidenceCount: item.evidenceIds.size,
      })),
    }))
    .sort((left, right) => left.tactic.localeCompare(right.tactic));
}

export function groupCrossSourceLinks(links: AnalysisResult["cross_source_links"]) {
  const groups = new Map<string, AnalysisResult["cross_source_links"]>();
  for (const link of links) {
    const group = groups.get(link.link_type) ?? [];
    group.push(link);
    groups.set(link.link_type, group);
  }
  return Array.from(groups.entries())
    .map(([type, groupLinks]) => ({ type, links: groupLinks }))
    .sort(
      (left, right) =>
        right.links.length - left.links.length || left.type.localeCompare(right.type),
    );
}

export function linkGroupLabel(type: string): string {
  const labels: Record<string, string> = {
    http_path_match: "HTTP path matches",
    dns_query_match: "DNS query matches",
    flow_match: "Flow matches",
  };
  return labels[type] ?? type;
}

export function buildCaseMetrics(result: AnalysisResult): { label: string; value: string }[] {
  const parserCount = new Set(result.sources.map((source) => source.parser)).size;
  const parsedRatio =
    result.raw_line_count === 0
      ? "0%"
      : `${Math.round((result.parsed_event_count / result.raw_line_count) * 100)}%`;
  const hashCoverage =
    result.sources.length === 0
      ? "0%"
      : `${Math.round(
          (result.sources.filter((source) => source.content_sha256.length >= 64).length /
            result.sources.length) *
            100,
        )}%`;
  return [
    { label: "Sources", value: String(result.sources.length) },
    { label: "Parsers", value: String(parserCount) },
    { label: "Parsed", value: parsedRatio },
    { label: "Findings", value: String(result.finding_count) },
    { label: "Incidents", value: String(result.incident_count) },
    { label: "Links", value: String(result.cross_source_links.length) },
    { label: "Hashes", value: hashCoverage },
  ];
}

export function buildCaseTimeline(
  result: AnalysisResult,
  selectedSourceId: string,
): CaseTimelineItem[] {
  const sourceById = new Map(result.sources.map((source) => [source.source_id, source.filename]));
  const sourceFilter =
    selectedSourceId === "all"
      ? null
      : result.sources.find((source) => source.source_id === selectedSourceId);
  const eventItems = result.events
    .filter((event) => !sourceFilter || event.source_id === sourceFilter.source_id)
    .slice(0, 80)
    .map((event) => ({
      id: event.id,
      timestamp: event.event_time,
      kind: "event" as const,
      source: sourceById.get(event.source_id) ?? event.source_id,
      summary: event.event_type,
      detail: event.message,
    }));
  const linkItems = result.cross_source_links
    .filter(
      (link) =>
        !sourceFilter ||
        link.source_label === sourceFilter.filename ||
        link.target_label === sourceFilter.filename,
    )
    .slice(0, 80)
    .map((link) => ({
      id: link.id,
      timestamp: link.event_time,
      kind: "link" as const,
      source: `${link.source_label} -> ${link.target_label}`,
      summary: link.link_type,
      detail: link.summary,
    }));
  return [...eventItems, ...linkItems]
    .sort((left, right) => {
      const leftTime = left.timestamp
        ? new Date(left.timestamp).getTime()
        : Number.MAX_SAFE_INTEGER;
      const rightTime = right.timestamp
        ? new Date(right.timestamp).getTime()
        : Number.MAX_SAFE_INTEGER;
      const kindOrder = left.kind === right.kind ? 0 : left.kind === "event" ? -1 : 1;
      return leftTime - rightTime || kindOrder || left.id.localeCompare(right.id);
    })
    .slice(0, 80);
}

export function stringValue(value: unknown): string | null {
  return value === null || value === undefined || value === "" ? null : String(value);
}

export function shortId(value: string): string {
  return value.length > 24 ? `${value.slice(0, 24)}...` : value;
}

export function formatScoreComponent(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function base64ToArrayBuffer(value: string): ArrayBuffer {
  const binary = window.atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

export function formatTimeRange(firstSeen: string, lastSeen: string): string {
  return `${formatTime(firstSeen)} - ${formatTime(lastSeen)}`;
}

export function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function higherSeverity(
  left: Finding["severity"],
  right: Finding["severity"],
): Finding["severity"] {
  const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return rank[right] > rank[left] ? right : left;
}
