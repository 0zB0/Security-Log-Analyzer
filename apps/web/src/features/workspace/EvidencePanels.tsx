import { FileSearch, Fingerprint } from "lucide-react";

import { EvidenceLine, Finding } from "../../lib/api";
import { FindingsPanel } from "./IncidentPanels";

export function EvidencePanel({
  finding,
  evidence,
}: {
  finding: Finding | null;
  evidence: EvidenceLine[];
}) {
  return (
    <section className="surface evidence-surface" data-tour="finding-evidence">
      <div className="surface-header">
        <div>
          <h2>Evidence</h2>
          <p>Exact raw lines behind the selected finding.</p>
        </div>
        {finding?.mitre.technique_id ? (
          <div className="mitre-chip">
            {finding.mitre.technique_id} {finding.mitre.technique_name}
          </div>
        ) : null}
      </div>

      {finding ? (
        <div className="finding-detail">
          <h3>{finding.reason}</h3>
          <div className="detail-grid">
            <span>Severity</span>
            <strong>{finding.severity}</strong>
            <span>Confidence</span>
            <strong>{finding.confidence}</strong>
            <span>Rule</span>
            <strong>{finding.rule_id}</strong>
          </div>
        </div>
      ) : null}

      {evidence.length === 0 ? (
        <div className="empty-state">Select a finding to inspect evidence.</div>
      ) : (
        <div className="evidence-viewer">
          {evidence.map((line) => (
            <div className="evidence-line" key={line.id}>
              <span className="line-number">{line.line_number}</span>
              <code>{line.raw_text}</code>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export function EvidenceReview({
  findings,
  selectedFinding,
  evidence,
  onSelectFinding,
  onOpenRule,
  emptyText = "No findings available. Upload a log or start live monitoring to inspect evidence.",
}: {
  findings: Finding[];
  selectedFinding: Finding | null;
  evidence: EvidenceLine[];
  onSelectFinding: (id: string) => void;
  onOpenRule: (ruleId: string) => void;
  emptyText?: string;
}) {
  return (
    <section className="evidence-workbench">
      <FindingsPanel
        findings={findings}
        selectedFinding={selectedFinding}
        onSelect={onSelectFinding}
        onOpenRule={onOpenRule}
        dataTour="evidence-findings"
        emptyText={emptyText}
      />
      <section className="surface evidence-main" data-tour="evidence-raw">
        <div className="surface-header">
          <div>
            <h2>Raw evidence</h2>
            <p>Line-level evidence preserved from the original local log source.</p>
          </div>
          <FileSearch size={18} />
        </div>
        {evidence.length === 0 ? (
          <div className="empty-state">Select a finding to review its captured evidence lines.</div>
        ) : (
          <div className="evidence-viewer evidence-reviewer">
            {evidence.map((line) => (
              <div className="evidence-line evidence-line-expanded" key={line.id}>
                <span className="line-number">{line.line_number}</span>
                <code>{line.raw_text}</code>
              </div>
            ))}
          </div>
        )}
      </section>
      <EvidenceMetadata finding={selectedFinding} evidence={evidence} />
    </section>
  );
}

function EvidenceMetadata({
  finding,
  evidence,
}: {
  finding: Finding | null;
  evidence: EvidenceLine[];
}) {
  return (
    <section className="surface evidence-metadata" data-tour="evidence-metadata">
      <div className="surface-header compact">
        <div>
          <h2>Evidence metadata</h2>
          <p>Rule, MITRE, count, and content hashes.</p>
        </div>
        <Fingerprint size={18} />
      </div>
      {finding ? (
        <>
          <div className="finding-detail metadata-block">
            <h3>{finding.title}</h3>
            <div className="detail-grid">
              <span>Rule</span>
              <strong>{finding.rule_id}</strong>
              <span>Severity</span>
              <strong>{finding.severity}</strong>
              <span>Confidence</span>
              <strong>{finding.confidence}</strong>
              <span>Events</span>
              <strong>{finding.event_count}</strong>
              <span>Evidence</span>
              <strong>{evidence.length} lines</strong>
              <span>MITRE</span>
              <strong>{finding.mitre.technique_id ?? "Unmapped"}</strong>
            </div>
          </div>
          <div className="hash-list">
            <h3>Content hashes</h3>
            {evidence.length === 0 ? (
              <div className="empty-state compact-empty">No evidence lines captured.</div>
            ) : (
              evidence.map((line) => (
                <div className="hash-row" key={line.id}>
                  <span>line {line.line_number}</span>
                  <code>{line.content_hash.slice(0, 16)}</code>
                </div>
              ))
            )}
          </div>
        </>
      ) : (
        <div className="empty-state">No finding selected.</div>
      )}
    </section>
  );
}
