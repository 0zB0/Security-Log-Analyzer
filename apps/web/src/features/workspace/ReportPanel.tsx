import { useMemo, useState } from "react";
import { ScrollText } from "lucide-react";

import {
  AnalysisResult,
  AssistantResponse,
  EvidenceLine,
  Finding,
  Incident,
  ReportResponse,
  generateCaseReport,
  generateIncidentReport,
  generatePublicCaseReport,
  generatePublicIncidentReport,
} from "../../lib/api";
import { ReportFormat } from "../../app/workspaceTypes";
import { base64ToArrayBuffer } from "./workspaceSelectors";

export function ReportPanel({
  result,
  selectedIncident,
  assistantResponse,
  reportFormat,
  report,
  onReport,
  onReportFormatChange,
  publicDemo = false,
}: {
  result: AnalysisResult | null;
  selectedIncident: Incident | null;
  assistantResponse: AssistantResponse | null;
  reportFormat: ReportFormat;
  report: ReportResponse | null;
  onReport: (report: ReportResponse | null) => void;
  onReportFormatChange: (format: ReportFormat) => void;
  publicDemo?: boolean;
}) {
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [redactSensitive, setRedactSensitive] = useState(false);
  const isCaseReport = result?.parser === "case_bundle";

  const linkedFindings = useMemo(() => {
    if (!result || !selectedIncident) {
      return [];
    }
    return selectedIncident.finding_ids
      .map((id) => result.findings.find((finding) => finding.id === id))
      .filter((finding): finding is Finding => Boolean(finding));
  }, [result, selectedIncident]);

  const linkedEvidence = useMemo(() => {
    if (!result || linkedFindings.length === 0) {
      return [];
    }
    const evidenceById = new Map(result.evidence.map((line) => [line.id, line]));
    const ids = new Set(linkedFindings.flatMap((finding) => finding.evidence_line_ids));
    return Array.from(ids)
      .map((id) => evidenceById.get(id))
      .filter((line): line is EvidenceLine => Boolean(line));
  }, [result, linkedFindings]);

  async function handleGenerate() {
    if (!result || (!isCaseReport && !selectedIncident)) {
      return;
    }
    setIsGenerating(true);
    setError(null);
    try {
      const generated = isCaseReport
        ? publicDemo
          ? await generatePublicCaseReport({
              analysis: result,
              redaction: {
                enabled: redactSensitive,
                mask_ips: true,
                mask_users: true,
                mask_hosts: true,
              },
            })
          : await generateCaseReport({
            analysis: result,
            assistant_summary: assistantResponse?.summary,
            format: reportFormat === "pdf" ? "pdf" : "markdown",
            redaction: {
              enabled: redactSensitive,
              mask_ips: true,
              mask_users: true,
              mask_hosts: true,
            },
          })
        : publicDemo
          ? await generatePublicIncidentReport({
              incident: selectedIncident as Incident,
              findings: linkedFindings,
              evidence: linkedEvidence,
              redaction: {
                enabled: redactSensitive,
                mask_ips: true,
                mask_users: true,
                mask_hosts: true,
              },
            })
          : await generateIncidentReport({
            incident: selectedIncident as Incident,
            findings: linkedFindings,
            evidence: linkedEvidence,
            assistant_summary: assistantResponse?.summary,
            format: reportFormat,
            redaction: {
              enabled: redactSensitive,
              mask_ips: true,
              mask_users: true,
              mask_hosts: true,
            },
          });
      onReport(generated);
    } catch (caught) {
      onReport(null);
      setError(caught instanceof Error ? caught.message : "Report generation failed");
    } finally {
      setIsGenerating(false);
    }
  }

  function handleDownload() {
    if (!report) {
      return;
    }
    const content =
      report.format === "pdf" ? base64ToArrayBuffer(report.content) : report.content;
    const mimeType =
      report.format === "pdf"
        ? "application/pdf"
        : report.format === "html"
          ? "text/html;charset=utf-8"
          : "text/markdown;charset=utf-8";
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = report.filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="report-grid">
      <section className="surface report-control" data-tour="report-controls">
        <div className="surface-header">
          <div>
            <h2>{isCaseReport ? "Case report" : "Incident report"}</h2>
            <p>
              {isCaseReport
                ? "Generate one report across all sources, incidents, cross-source links, and evidence hashes."
                : "Generate a local Markdown, HTML, or PDF report from deterministic findings and evidence."}
            </p>
          </div>
          <ScrollText size={18} />
        </div>
        <div className="assistant-body">
          <div className="detail-grid">
            <span>Incident</span>
            <strong>{isCaseReport ? result?.source_id ?? "None" : selectedIncident?.title ?? "None"}</strong>
            <span>Findings</span>
            <strong>{isCaseReport ? result?.finding_count ?? 0 : linkedFindings.length}</strong>
            <span>Evidence</span>
            <strong>{isCaseReport ? result?.evidence.length ?? 0 : linkedEvidence.length} lines</strong>
            <span>Assistant</span>
            <strong>{assistantResponse ? "included" : "not included"}</strong>
            {isCaseReport ? (
              <>
                <span>Sources</span>
                <strong>{result?.sources.length ?? 0}</strong>
                <span>Links</span>
                <strong>{result?.cross_source_links.length ?? 0}</strong>
              </>
            ) : null}
          </div>
          <div className="report-format">
            <span>Format</span>
            <div className="segmented-control">
              <button
                className={reportFormat === "markdown" ? "selected" : ""}
                onClick={() => onReportFormatChange("markdown")}
              >
                Markdown
              </button>
              <button
                className={reportFormat === "html" ? "selected" : ""}
                onClick={() => onReportFormatChange("html")}
                disabled={isCaseReport}
                hidden={publicDemo}
              >
                HTML
              </button>
              <button
                className={reportFormat === "pdf" ? "selected" : ""}
                onClick={() => onReportFormatChange("pdf")}
                hidden={publicDemo}
              >
                PDF
              </button>
            </div>
            {publicDemo ? (
              <span className="session-note">Public demo reports are Markdown-only.</span>
            ) : null}
          </div>
          <label className="toggle-row" data-tour="report-redaction">
            <input
              type="checkbox"
              checked={redactSensitive}
              onChange={(event) => setRedactSensitive(event.target.checked)}
            />
            <span>Redact IPs, users, and hosts</span>
          </label>
          {error ? <div className="error-banner">{error}</div> : null}
          <div className="report-actions">
            <button
              className="upload-button"
              onClick={handleGenerate}
              disabled={(!isCaseReport && !selectedIncident) || isGenerating}
              data-tour="report-generate"
            >
              <ScrollText size={16} /> {isGenerating ? "Generating" : "Generate report"}
            </button>
            <button
              className="stop-button"
              onClick={handleDownload}
              disabled={!report}
              data-tour="report-download"
            >
              Download {report ? `.${report.filename.split(".").pop()}` : ""}
            </button>
          </div>
        </div>
      </section>
      <section className="surface report-preview" data-tour="report-preview">
        <div className="surface-header">
          <div>
            <h2>Preview</h2>
            <p>{report ? report.filename : "No report generated yet."}</p>
          </div>
          <ScrollText size={18} />
        </div>
        {report ? (
          report.format === "pdf" ? (
            <iframe
              className="html-report-preview"
              title="PDF report preview"
              src={`data:application/pdf;base64,${report.content}`}
            />
          ) : report.format === "html" ? (
            <iframe className="html-report-preview" title="HTML report preview" srcDoc={report.content} />
          ) : (
            <pre>{report.content}</pre>
          )
        ) : (
          <div className="empty-state">Generate a report for the selected incident.</div>
        )}
      </section>
    </section>
  );
}
