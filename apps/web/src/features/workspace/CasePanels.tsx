import { useMemo, useState } from "react";
import { Activity, Clock3, Fingerprint, ListFilter, Network } from "lucide-react";

import { AnalysisResult, EvidenceLine } from "../../lib/api";
import { buildCaseMetrics, buildCaseTimeline, CaseTimelineItem, formatTime, groupCrossSourceLinks, linkGroupLabel, shortId, stringValue } from "./workspaceSelectors";
import { IncidentOverview } from "./IncidentPanels";

export function MetricGrid({
  result,
  isAnalyzing,
}: {
  result: AnalysisResult | null;
  isAnalyzing: boolean;
}) {
  const metrics = [
    ["Parser", result?.parser ?? (isAnalyzing ? "Running" : "Waiting")],
    ["Raw lines", result?.raw_line_count.toString() ?? "0"],
    ["Events", result?.parsed_event_count.toString() ?? "0"],
    ["Findings", result?.finding_count.toString() ?? "0"],
    ["Incidents", result?.incident_count.toString() ?? "0"],
  ];

  return (
    <section className="metrics">
      {metrics.map(([label, value]) => (
        <div className="metric" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </section>
  );
}

export function CaseOverview({ result }: { result: AnalysisResult | null }) {
  const [selectedLinkId, setSelectedLinkId] = useState<string | null>(null);
  const [selectedSourceId, setSelectedSourceId] = useState<string>("all");
  const caseMetrics = useMemo(() => (result ? buildCaseMetrics(result) : []), [result]);
  const filteredLinks = useMemo(() => {
    if (!result) {
      return [];
    }
    if (selectedSourceId === "all") {
      return result.cross_source_links;
    }
    const source = result.sources.find((item) => item.source_id === selectedSourceId);
    if (!source) {
      return result.cross_source_links;
    }
    return result.cross_source_links.filter(
      (link) => link.source_label === source.filename || link.target_label === source.filename,
    );
  }, [result, selectedSourceId]);
  const selectedLink = useMemo(() => {
    if (!filteredLinks.length) {
      return null;
    }
    return filteredLinks.find((link) => link.id === selectedLinkId) ?? filteredLinks[0];
  }, [filteredLinks, selectedLinkId]);
  const caseTimeline = useMemo(() => (result ? buildCaseTimeline(result, selectedSourceId) : []), [
    result,
    selectedSourceId,
  ]);
  const groupedLinks = useMemo(() => groupCrossSourceLinks(filteredLinks), [filteredLinks]);

  if (!result) {
    return (
      <section className="surface case-surface">
        <div className="surface-header">
          <div>
            <h2>Case bundle</h2>
            <p>Import multiple Zeek and Suricata exports to build one correlated investigation.</p>
          </div>
          <Network size={18} />
        </div>
        <div className="empty-state">No case loaded.</div>
      </section>
    );
  }

  return (
    <section className="case-workbench">
      <section className="case-summary-grid">
        {caseMetrics.map((metric) => (
          <div className="metric case-metric" key={metric.label}>
            <span>{metric.label}</span>
            <strong>{metric.value}</strong>
          </div>
        ))}
      </section>
      {result.case_quality ? <CaseQualityPanel quality={result.case_quality} /> : null}
      <section className="surface case-surface">
        <div className="surface-header">
          <div>
            <h2>Sources</h2>
            <p>{result.sources.length} source files with parser, count, and hash checks.</p>
          </div>
          <Network size={18} />
        </div>
        <div className="case-filter-row">
          <label htmlFor="case-source-filter">Source filter</label>
          <select
            id="case-source-filter"
            value={selectedSourceId}
            onChange={(event) => {
              setSelectedSourceId(event.target.value);
              setSelectedLinkId(null);
            }}
          >
            <option value="all">All sources</option>
            {result.sources.map((source) => (
              <option key={source.source_id} value={source.source_id}>
                {source.filename}
              </option>
            ))}
          </select>
        </div>
        {result.sources.length === 0 ? (
          <div className="empty-state">This analysis has no source summary.</div>
        ) : (
          <div className="source-table">
            {result.sources.map((source) => (
              <button
                className={`source-row ${selectedSourceId === source.source_id ? "selected" : ""}`}
                key={source.source_id}
                onClick={() => {
                  setSelectedSourceId(source.source_id);
                  setSelectedLinkId(null);
                }}
              >
                <strong>{source.filename}</strong>
                <span>{source.parser}</span>
                <span>{source.parsed_event_count}/{source.raw_line_count} parsed</span>
                <span>{source.finding_count} findings</span>
                <code>{source.content_sha256.slice(0, 16)}</code>
              </button>
            ))}
          </div>
        )}
      </section>
      <section className="surface case-surface">
        <div className="surface-header">
          <div>
            <h2>Cross-source links</h2>
            <p>{filteredLinks.length} visible joins across Zeek and Suricata.</p>
          </div>
          <ListFilter size={18} />
        </div>
        {filteredLinks.length === 0 ? (
          <div className="empty-state">No cross-source links found.</div>
        ) : (
          <div className="link-list">
            {groupedLinks.map((group) => (
              <div className="link-group" key={group.type}>
                <div className="link-group-header">
                  <strong>{linkGroupLabel(group.type)}</strong>
                  <span>{group.links.length}</span>
                </div>
                {group.links.slice(0, 16).map((link) => (
                  <button
                    className={`link-row ${selectedLink?.id === link.id ? "selected" : ""}`}
                    key={link.id}
                    onClick={() => setSelectedLinkId(link.id)}
                  >
                    <div>
                      <strong>{link.link_type}</strong>
                      <p>{link.summary}</p>
                    </div>
                    <div className="finding-meta">
                      <span>{link.source_label}</span>
                      <span>{link.target_label}</span>
                      <span>{link.match_value ?? "matched"}</span>
                      <span>{link.confidence}</span>
                    </div>
                  </button>
                ))}
              </div>
            ))}
          </div>
        )}
      </section>
      <CaseTimeline items={caseTimeline} />
      <CaseLinkDetail result={result} link={selectedLink} />
      <IncidentOverview
        incidents={result.incidents}
        selectedIncident={result.incidents[0] ?? null}
        onSelectIncident={() => undefined}
      />
    </section>
  );
}

function CaseQualityPanel({ quality }: { quality: NonNullable<AnalysisResult["case_quality"]> }) {
  return (
    <section className="surface case-quality-panel">
      <div className="surface-header compact">
        <div>
          <h2>Case quality</h2>
          <p>{quality.top_scoring_reason ?? "No scoring rationale supplied."}</p>
        </div>
        <Activity size={18} />
      </div>
      <div className="case-quality-grid">
        <div>
          <span>Strongest incident</span>
          <strong>{quality.strongest_incident_title ?? "None"}</strong>
        </div>
        <div>
          <span>Top score</span>
          <strong>{quality.strongest_incident_score}</strong>
        </div>
        <div>
          <span>Sequence backed</span>
          <strong>{quality.sequence_backed_incident_count}</strong>
        </div>
        <div>
          <span>Cross-source backed</span>
          <strong>{quality.cross_source_corroborated_incident_count}</strong>
        </div>
        <div>
          <span>Total links</span>
          <strong>{quality.total_cross_source_links}</strong>
        </div>
      </div>
    </section>
  );
}

function CaseTimeline({ items }: { items: CaseTimelineItem[] }) {
  return (
    <section className="surface case-timeline-surface">
      <div className="surface-header">
        <div>
          <h2>Case timeline</h2>
          <p>Events and cross-source joins ordered for analyst review.</p>
        </div>
        <Clock3 size={18} />
      </div>
      {items.length === 0 ? (
        <div className="empty-state">No timeline entries for this case.</div>
      ) : (
        <ol className="case-timeline">
          {items.map((item, index) => (
            <li key={item.id}>
              <span className="timeline-index">{index + 1}</span>
              <div>
                <div className="case-timeline-title">
                  <strong>{item.summary}</strong>
                  <span>{item.kind}</span>
                  <time>{item.timestamp ? formatTime(item.timestamp) : "unknown-time"}</time>
                </div>
                <p>{item.detail}</p>
                <code>{item.source}</code>
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function CaseLinkDetail({
  result,
  link,
}: {
  result: AnalysisResult;
  link: AnalysisResult["cross_source_links"][number] | null;
}) {
  const eventById = new Map(result.events.map((event) => [event.id, event]));
  const evidenceById = new Map(result.evidence.map((line) => [line.id, line]));
  const sourceEvent = link ? eventById.get(link.source_event_id) ?? null : null;
  const targetEvent = link ? eventById.get(link.target_event_id) ?? null : null;
  const sourceEvidence = link ? evidenceById.get(link.source_raw_line_id) ?? null : null;
  const targetEvidence = link ? evidenceById.get(link.target_raw_line_id) ?? null : null;

  return (
    <section className="surface case-link-detail">
      <div className="surface-header">
        <div>
          <h2>Link evidence</h2>
          <p>Side-by-side Suricata and Zeek evidence for the selected correlation.</p>
        </div>
        <Fingerprint size={18} />
      </div>
      {!link ? (
        <div className="empty-state">No cross-source link selected.</div>
      ) : (
        <>
          <div className="detail-grid case-link-meta">
            <span>Type</span>
            <strong>{link.link_type}</strong>
            <span>Match</span>
            <strong>{link.match_value ?? "n/a"}</strong>
            <span>Source IP</span>
            <strong>{link.source_ip ?? "n/a"}</strong>
            <span>Destination</span>
            <strong>
              {link.destination_ip ?? "n/a"}:{link.destination_port ?? "n/a"}
            </strong>
            <span>Time</span>
            <strong>{link.event_time ? formatTime(link.event_time) : "n/a"}</strong>
            <span>Raw lines</span>
            <strong>
              {shortId(link.source_raw_line_id)} {"->"} {shortId(link.target_raw_line_id)}
            </strong>
          </div>
          <div className="case-evidence-pair">
            <CaseEvidenceCard
              title={link.source_label}
              event={sourceEvent}
              evidence={sourceEvidence}
            />
            <CaseEvidenceCard
              title={link.target_label}
              event={targetEvent}
              evidence={targetEvidence}
            />
          </div>
        </>
      )}
    </section>
  );
}

function CaseEvidenceCard({
  title,
  event,
  evidence,
}: {
  title: string;
  event: AnalysisResult["events"][number] | null;
  evidence: EvidenceLine | null;
}) {
  const destinationIp = event?.normalized_fields.destination_ip;
  const destinationPort = event?.normalized_fields.destination_port;
  const dnsQuery = event?.normalized_fields.dns_query;
  const urlPath = event?.normalized_fields.url_path;

  return (
    <div className="case-evidence-card">
      <div className="finding-title-row">
        <strong>{title}</strong>
        <span className="mitre-chip">{event?.event_type ?? "missing event"}</span>
      </div>
      <div className="detail-grid">
        <span>Timestamp</span>
        <strong>{event?.event_time ? formatTime(event.event_time) : "n/a"}</strong>
        <span>Source</span>
        <strong>{event?.source_ip ?? "n/a"}</strong>
        <span>Destination</span>
        <strong>
          {stringValue(destinationIp) ?? "n/a"}:{stringValue(destinationPort) ?? "n/a"}
        </strong>
        <span>DNS/HTTP</span>
        <strong>{stringValue(dnsQuery) ?? stringValue(urlPath) ?? "n/a"}</strong>
      </div>
      {evidence ? (
        <div className="evidence-line evidence-line-expanded">
          <span className="line-number">{evidence.line_number}</span>
          <code>{evidence.raw_text}</code>
          <span />
          <code>{evidence.content_hash}</code>
        </div>
      ) : (
        <div className="empty-state compact-empty">Raw evidence line not found.</div>
      )}
    </div>
  );
}
