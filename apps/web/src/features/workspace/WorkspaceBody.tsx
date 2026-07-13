import type {
  AnalysisResult,
  AssistantResponse,
  AssistantStatus,
  EvidenceLine,
  Finding,
  Incident,
  ReportResponse,
} from "../../lib/api";
import type { ReportFormat, WorkspaceView } from "../../app/workspaceTypes";
import { AssistantPanel, SettingsPanel } from "./AssistantPanels";
import { CaseOverview } from "./CasePanels";
import { EvidencePanel, EvidenceReview } from "./EvidencePanels";
import { FindingsPanel, IncidentDetail, IncidentOverview } from "./IncidentPanels";
import { DetectionLibrary, EntityInventory, MitreMapPanel } from "./KnowledgePanels";
import { ReportPanel } from "./ReportPanel";
import { filterFindingsByQuery } from "./workspaceSelectors";

export { MetricGrid } from "./CasePanels";
export { LiveMonitor, snapshotToAnalysisResult } from "./LiveMonitor";

interface WorkspaceBodyProps {
  activeView: WorkspaceView;
  result: AnalysisResult | null;
  selectedIncident: Incident | null;
  selectedFinding: Finding | null;
  evidenceForFinding: EvidenceLine[];
  searchQuery: string;
  assistantResponse: AssistantResponse | null;
  assistantStatus: AssistantStatus | null;
  reportFormat: ReportFormat;
  onAssistantResponse: (response: AssistantResponse | null) => void;
  reportResponse: ReportResponse | null;
  onReportResponse: (response: ReportResponse | null) => void;
  onReportFormatChange: (format: ReportFormat) => void;
  selectedRuleId: string | null;
  onSelectRule: (ruleId: string) => void;
  onSelectIncident: (incident: Incident) => void;
  onSelectFinding: (id: string) => void;
  publicDemo?: boolean;
}

export function WorkspaceBody({
  activeView,
  result,
  selectedIncident,
  selectedFinding,
  evidenceForFinding,
  searchQuery,
  assistantResponse,
  assistantStatus,
  reportFormat,
  onAssistantResponse,
  reportResponse,
  onReportResponse,
  onReportFormatChange,
  selectedRuleId,
  onSelectRule,
  onSelectIncident,
  onSelectFinding,
  publicDemo = false,
}: WorkspaceBodyProps) {
  const visibleFindings = filterFindingsByQuery(result?.findings ?? [], searchQuery);
  const visibleSelectedFinding =
    visibleFindings.find((finding) => finding.id === selectedFinding?.id) ??
    visibleFindings[0] ??
    null;
  const visibleEvidence =
    visibleSelectedFinding?.id === selectedFinding?.id
      ? evidenceForFinding
      : (result?.evidence ?? []).filter((line) =>
          visibleSelectedFinding?.evidence_line_ids.includes(line.id),
        );

  if (activeView === "assistant") {
    return (
      <AssistantPanel
        result={result}
        selectedIncident={selectedIncident}
        response={assistantResponse}
        status={assistantStatus}
        onResponse={onAssistantResponse}
      />
    );
  }
  if (activeView === "settings") {
    return <SettingsPanel result={result} selectedIncident={selectedIncident} />;
  }
  if (activeView === "reports") {
    return (
      <ReportPanel
        result={result}
        selectedIncident={selectedIncident}
        assistantResponse={assistantResponse}
        reportFormat={reportFormat}
        report={reportResponse}
        onReport={onReportResponse}
        onReportFormatChange={onReportFormatChange}
        publicDemo={publicDemo}
      />
    );
  }
  if (activeView === "library") {
    return (
      <DetectionLibrary
        result={result}
        selectedRuleId={selectedRuleId}
        onSelectRule={onSelectRule}
      />
    );
  }
  if (activeView === "entities") {
    return (
      <EntityInventory
        result={result}
        onSelectIncident={onSelectIncident}
        onSelectFinding={onSelectFinding}
      />
    );
  }
  if (activeView === "mitre") {
    return <MitreMapPanel result={result} onSelectFinding={onSelectFinding} />;
  }
  if (activeView === "incidents") {
    return (
      <section className="incident-workbench">
        <IncidentOverview
          incidents={result?.incidents ?? []}
          selectedIncident={selectedIncident}
          onSelectIncident={onSelectIncident}
        />
        <IncidentDetail
          analysisId={result?.analysis_id ?? null}
          incident={selectedIncident}
          findings={result?.findings ?? []}
          onSelectFinding={onSelectFinding}
        />
      </section>
    );
  }
  if (activeView === "findings") {
    return (
      <section className="analysis-grid findings-only-grid">
        <FindingsPanel
          findings={visibleFindings}
          selectedFinding={visibleSelectedFinding}
          onSelect={onSelectFinding}
          onOpenRule={onSelectRule}
          emptyText="No findings yet. Upload a supported text log or run a sample."
        />
        <EvidencePanel finding={visibleSelectedFinding} evidence={visibleEvidence} />
      </section>
    );
  }
  if (activeView === "case") {
    return <CaseOverview result={result} />;
  }
  if (activeView === "evidence") {
    return (
      <EvidenceReview
        findings={visibleFindings}
        selectedFinding={visibleSelectedFinding}
        evidence={visibleEvidence}
        onSelectFinding={onSelectFinding}
        onOpenRule={onSelectRule}
        emptyText={
          searchQuery.trim()
            ? "No findings match the current search."
            : "No findings available. Upload a log or start live monitoring to inspect evidence."
        }
      />
    );
  }
  return (
    <>
      <IncidentOverview
        incidents={result?.incidents ?? []}
        selectedIncident={selectedIncident}
        onSelectIncident={onSelectIncident}
      />
      <section className="analysis-grid">
        <FindingsPanel
          findings={visibleFindings}
          selectedFinding={visibleSelectedFinding}
          onSelect={onSelectFinding}
          onOpenRule={onSelectRule}
          emptyText={
            searchQuery.trim()
              ? "No findings match the current search."
              : activeView === "live"
              ? "No findings yet. Start live monitoring or append matching log lines to the watched file."
              : "No findings yet. Upload a supported auth, web, Zeek, Suricata, JSON, CSV, or syslog file to test the rule engine."
          }
        />
        <EvidencePanel finding={visibleSelectedFinding} evidence={visibleEvidence} />
      </section>
    </>
  );
}
