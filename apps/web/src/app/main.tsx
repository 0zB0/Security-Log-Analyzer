import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  BookOpen,
  BrainCircuit,
  FileSearch,
  FileUp,
  Fingerprint,
  Network,
  RadioTower,
  Search,
  SlidersHorizontal,
  ScrollText,
} from "lucide-react";
import {
  AnalysisResult,
  AssistantResponse,
  AssistantStatus,
  AuthStatus,
  EvidenceLine,
  LiveSnapshot,
  ReportResponse,
  analyzeCaseBundle,
  analyzeDemo,
  analyzeRealLabCase,
  analyzeSample,
  analyzeUpload,
  getAssistantStatus,
  getAuthStatus,
} from "../lib/api";
import { LiveMonitor, MetricGrid, WorkspaceBody, snapshotToAnalysisResult } from "../features/workspace/WorkspaceBody";
import { SAMPLE_OPTIONS } from "./workspaceOptions";
import { ReportFormat, WorkspaceView } from "./workspaceTypes";
import "../styles/main.css";

function App() {
  const [activeView, setActiveView] = useState<WorkspaceView>("upload");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [assistantResponse, setAssistantResponse] = useState<AssistantResponse | null>(null);
  const [assistantStatus, setAssistantStatus] = useState<AssistantStatus | null>(null);
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [reportResponse, setReportResponse] = useState<ReportResponse | null>(null);
  const [reportFormat, setReportFormat] = useState<ReportFormat>("markdown");
  const [sampleId, setSampleId] = useState(SAMPLE_OPTIONS[0].id);
  const [libraryRuleId, setLibraryRuleId] = useState<string | null>(null);
  const [latestLiveSnapshot, setLatestLiveSnapshot] = useState<LiveSnapshot | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedFinding = useMemo(() => {
    if (!result) {
      return null;
    }
    return (
      result.findings.find((finding) => finding.id === selectedFindingId) ??
      result.findings[0] ??
      null
    );
  }, [result, selectedFindingId]);

  const selectedIncident = useMemo(() => {
    if (!result) {
      return null;
    }
    return (
      result.incidents.find((incident) => incident.id === selectedIncidentId) ??
      result.incidents[0] ??
      null
    );
  }, [result, selectedIncidentId]);

  const evidenceForFinding = useMemo(() => {
    if (!result || !selectedFinding) {
      return [];
    }
    const evidenceById = new Map(result.evidence.map((line) => [line.id, line]));
    return selectedFinding.evidence_line_ids
      .map((id) => evidenceById.get(id))
      .filter((line): line is EvidenceLine => Boolean(line));
  }, [result, selectedFinding]);

  useEffect(() => {
    let isMounted = true;
    getAuthStatus()
      .then((status) => {
        if (isMounted) {
          setAuthStatus(status);
        }
      })
      .catch(() => {
        if (isMounted) {
          setAuthStatus(null);
        }
      });
    getAssistantStatus()
      .then((status) => {
        if (isMounted) {
          setAssistantStatus(status);
        }
      })
      .catch(() => {
        if (isMounted) {
          setAssistantStatus({
            enabled: false,
            provider: "unknown",
            url: "",
            model: null,
            available: false,
            installed_models: [],
            error: "Assistant API unavailable",
          });
        }
      });
    return () => {
      isMounted = false;
    };
  }, []);

  async function handleFileChange(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    setIsAnalyzing(true);
    setError(null);
    try {
      const analysis = await analyzeUpload(file);
      setResult(analysis);
      setSelectedIncidentId(analysis.incidents[0]?.id ?? null);
      setSelectedFindingId(analysis.findings[0]?.id ?? null);
      setActiveView("incidents");
    } catch (caught) {
      setResult(null);
      setSelectedFindingId(null);
      setError(caught instanceof Error ? caught.message : "Analysis failed");
    } finally {
      setIsAnalyzing(false);
      event.target.value = "";
    }
  }

  async function handleRunDemo() {
    setIsAnalyzing(true);
    setError(null);
    try {
      const analysis = await analyzeDemo();
      setResult(analysis);
      setSelectedIncidentId(analysis.incidents[0]?.id ?? null);
      setSelectedFindingId(analysis.findings[0]?.id ?? null);
      setActiveView("incidents");
    } catch (caught) {
      setResult(null);
      setSelectedIncidentId(null);
      setSelectedFindingId(null);
      setError(caught instanceof Error ? caught.message : "Demo analysis failed");
    } finally {
      setIsAnalyzing(false);
    }
  }

  async function handleRunSample() {
    setIsAnalyzing(true);
    setError(null);
    try {
      const analysis = await analyzeSample(sampleId);
      setResult(analysis);
      setSelectedIncidentId(analysis.incidents[0]?.id ?? null);
      setSelectedFindingId(analysis.findings[0]?.id ?? null);
      setActiveView("incidents");
    } catch (caught) {
      setResult(null);
      setSelectedIncidentId(null);
      setSelectedFindingId(null);
      setError(caught instanceof Error ? caught.message : "Sample analysis failed");
    } finally {
      setIsAnalyzing(false);
    }
  }

  async function handleCaseBundleChange(event: React.ChangeEvent<HTMLInputElement>) {
    const files = event.target.files;
    if (!files?.length) {
      return;
    }
    setIsAnalyzing(true);
    setError(null);
    try {
      const analysis = await analyzeCaseBundle(files);
      setResult(analysis);
      setSelectedIncidentId(analysis.incidents[0]?.id ?? null);
      setSelectedFindingId(analysis.findings[0]?.id ?? null);
      setActiveView("case");
    } catch (caught) {
      setResult(null);
      setSelectedIncidentId(null);
      setSelectedFindingId(null);
      setError(caught instanceof Error ? caught.message : "Case bundle analysis failed");
    } finally {
      setIsAnalyzing(false);
      event.target.value = "";
    }
  }

  async function handleRunRealLabCase() {
    setIsAnalyzing(true);
    setError(null);
    try {
      const analysis = await analyzeRealLabCase();
      setResult(analysis);
      setSelectedIncidentId(analysis.incidents[0]?.id ?? null);
      setSelectedFindingId(analysis.findings[0]?.id ?? null);
      setActiveView("case");
    } catch (caught) {
      setResult(null);
      setSelectedIncidentId(null);
      setSelectedFindingId(null);
      setError(caught instanceof Error ? caught.message : "Real lab case analysis failed");
    } finally {
      setIsAnalyzing(false);
    }
  }

  return (
    <main className="shell">
      <section className="topbar">
        <div className="brand">
          <span className="breadcrumb">SOC / Log Analyzer /</span>
          <strong>{viewTitle(activeView)}</strong>
          <span className="version-pill">
            <span className="status-dot" />
            TraceHawk v0.7.1
          </span>
        </div>
        <div className="topbar-actions">
          <span className="demo-label">{authLabel(authStatus)}</span>
          {authStatus?.allowlist_enabled ? (
            <div className="auth-links">
              <a href="/.auth/login/google?post_login_redirect_uri=%2F">Login</a>
              <a href="/.auth/logout?post_logout_redirect_uri=%2F">Logout</a>
            </div>
          ) : null}
          <div className={`status ${assistantStatus?.enabled ? "" : "muted"}`}>
            {assistantStatus
              ? `${assistantStatus.provider.toUpperCase()} ${
                  assistantStatus.enabled ? "READY" : "UNAVAILABLE"
                }`
              : "AI STATUS"}
          </div>
        </div>
      </section>
      <section className="commandbar">
        <label className="search-box">
          <Search size={16} />
          <input
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            placeholder="Search findings, IPs, users, rules"
          />
        </label>
        <span className="toolbar-button">Data tier: Evidence</span>
        <span className="toolbar-button">Last 24 hours</span>
        <button className="toolbar-button primary" onClick={() => window.location.reload()}>
          Refresh
        </button>
      </section>
      <section className="workspace">
        <aside className="sidebar">
          <button
            className={activeView === "upload" ? "nav-active" : ""}
            onClick={() => setActiveView("upload")}
          >
            <FileUp size={16} /> Upload
          </button>
          <button
            className={activeView === "case" ? "nav-active" : ""}
            onClick={() => setActiveView("case")}
          >
            <Network size={16} /> Case
          </button>
          <button
            className={activeView === "live" ? "nav-active" : ""}
            onClick={() => setActiveView("live")}
          >
            <RadioTower size={16} /> Live Monitor
          </button>
          <button
            className={activeView === "entities" ? "nav-active" : ""}
            onClick={() => setActiveView("entities")}
          >
            <Fingerprint size={16} /> Entities
          </button>
          <button
            className={activeView === "mitre" ? "nav-active" : ""}
            onClick={() => setActiveView("mitre")}
          >
            <Activity size={16} /> MITRE
          </button>
          <button
            className={activeView === "incidents" ? "nav-active" : ""}
            onClick={() => setActiveView("incidents")}
          >
            <AlertTriangle size={16} /> Incidents
          </button>
          <button
            className={activeView === "evidence" ? "nav-active" : ""}
            onClick={() => setActiveView("evidence")}
          >
            <FileSearch size={16} /> Evidence
          </button>
          <button
            className={activeView === "assistant" ? "nav-active" : ""}
            onClick={() => setActiveView("assistant")}
          >
            <BrainCircuit size={16} /> Local AI
          </button>
          <button
            className={activeView === "reports" ? "nav-active" : ""}
            onClick={() => setActiveView("reports")}
          >
            <ScrollText size={16} /> Reports
          </button>
          <button
            className={activeView === "library" ? "nav-active" : ""}
            onClick={() => setActiveView("library")}
          >
            <BookOpen size={16} /> Library
          </button>
          <button
            className={activeView === "settings" ? "nav-active" : ""}
            onClick={() => setActiveView("settings")}
          >
            <SlidersHorizontal size={16} /> Settings
          </button>
        </aside>
        <section className="panel investigation">
          <section className="intake-strip">
            <div className="intake-title">[Investigation intake]</div>
            <div className="intake-subtle">
              {result ? `${result.raw_line_count} lines loaded` : "No file selected"}
            </div>
            <div className="intake-controls">
              <label className="file-inline">
                <span>Browse...</span>
                <input
                  type="file"
                  accept=".log,.txt,.csv,.json,.jsonl,text/plain,application/json"
                  onChange={handleFileChange}
                  disabled={isAnalyzing}
                />
              </label>
              <div className="file-status">
                {result ? `${result.parser} / ${result.finding_count} findings` : "No file selected."}
              </div>
              <button
                className="upload-button inline-action"
                onClick={handleRunDemo}
                disabled={isAnalyzing}
              >
                Run demo
              </button>
              <select
                aria-label="Sample scenario"
                className="sample-select"
                value={sampleId}
                onChange={(event) => setSampleId(event.target.value)}
                disabled={isAnalyzing}
              >
                {SAMPLE_OPTIONS.map((sample) => (
                  <option key={sample.id} value={sample.id}>
                    {sample.label}
                  </option>
                ))}
              </select>
              <button className="stop-button" onClick={handleRunSample} disabled={isAnalyzing}>
                Run sample
              </button>
              <label className="file-inline">
                <span>Case...</span>
                <input
                  type="file"
                  multiple
                  accept=".log,.txt,.csv,.json,.jsonl,text/plain,application/json"
                  onChange={handleCaseBundleChange}
                  disabled={isAnalyzing}
                />
              </label>
              <button
                className="stop-button"
                onClick={handleRunRealLabCase}
                disabled={isAnalyzing}
              >
                Real lab case
              </button>
              <button
                className="stop-button"
                onClick={() => {
                  setReportFormat("markdown");
                  setActiveView("reports");
                }}
              >
                Markdown
              </button>
              <button
                className="stop-button"
                onClick={() => {
                  setReportFormat("pdf");
                  setActiveView("reports");
                }}
              >
                PDF
              </button>
            </div>
          </section>
          <header className="panel-header">
            <div>
              <h1>{viewTitle(activeView)}</h1>
              <p>{viewDescription(activeView)}</p>
            </div>
          </header>

          {error ? <div className="error-banner">{error}</div> : null}

          {activeView === "live" ? (
            <LiveMonitor
              initialSnapshot={latestLiveSnapshot}
              onSnapshot={(snapshot) => {
                setLatestLiveSnapshot(snapshot);
                const liveResult = snapshotToAnalysisResult(snapshot);
                setResult(liveResult);
                setSelectedIncidentId((current) => current ?? liveResult.incidents[0]?.id ?? null);
                setSelectedFindingId((current) => current ?? liveResult.findings[0]?.id ?? null);
              }}
              onSaved={(analysis) => {
                setResult(analysis);
                setSelectedIncidentId(analysis.incidents[0]?.id ?? null);
                setSelectedFindingId(analysis.findings[0]?.id ?? null);
                setActiveView("incidents");
              }}
              onError={setError}
            />
          ) : null}

          {activeView !== "library" ? <MetricGrid result={result} isAnalyzing={isAnalyzing} /> : null}

          <WorkspaceBody
            activeView={activeView}
            result={result}
            selectedIncident={selectedIncident}
            selectedFinding={selectedFinding}
            evidenceForFinding={evidenceForFinding}
            assistantResponse={assistantResponse}
            assistantStatus={assistantStatus}
            reportFormat={reportFormat}
            onAssistantResponse={setAssistantResponse}
            reportResponse={reportResponse}
            onReportResponse={setReportResponse}
            onReportFormatChange={setReportFormat}
            selectedRuleId={libraryRuleId}
            onSelectRule={(ruleId) => {
              setLibraryRuleId(ruleId);
              setActiveView("library");
            }}
            onSelectIncident={(incident) => {
              setSelectedIncidentId(incident.id);
              setSelectedFindingId(incident.finding_ids[0] ?? null);
            }}
            onSelectFinding={setSelectedFindingId}
          />
        </section>
      </section>
    </main>
  );
}

function authLabel(status: AuthStatus | null): string {
  if (!status?.allowlist_enabled) {
    return "Local-only demo";
  }
  if (status.allowed && status.email) {
    return `Signed in: ${status.email}`;
  }
  if (status.authenticated && status.email) {
    return `Account denied: ${status.email}`;
  }
  return "Sign in required";
}

function viewTitle(view: WorkspaceView): string {
  switch (view) {
    case "case":
      return "Case investigation";
    case "live":
      return "Live monitor";
    case "entities":
      return "Entities";
    case "mitre":
      return "MITRE map";
    case "incidents":
      return "Incident desk";
    case "evidence":
      return "Evidence review";
    case "assistant":
      return "Local AI";
    case "reports":
      return "Reports";
    case "library":
      return "Detection library";
    case "settings":
      return "Settings";
    case "upload":
      return "Investigation workspace";
  }
}

function viewDescription(view: WorkspaceView): string {
  switch (view) {
    case "case":
      return "Import multiple Zeek and Suricata exports as one investigation, correlate shared flows, DNS queries, HTTP paths, and generate a case report.";
    case "live":
      return "Watch a local log file or packet metadata from an approved network interface.";
    case "entities":
      return "Review extracted IPs, users, hosts, services, paths, and domains with linked findings and incidents.";
    case "mitre":
      return "Group findings by MITRE tactic and technique with linked rules and evidence counts.";
    case "incidents":
      return "Review correlated security stories, linked findings, entity context, MITRE techniques, and the investigation timeline.";
    case "evidence":
      return "Inspect the exact raw log lines behind each finding without losing rule, severity, and MITRE context.";
    case "assistant":
      return "Local LLM assistance will explain selected incidents with evidence references when Ollama integration is enabled.";
    case "reports":
      return "Generate local Markdown, HTML, or PDF incident reports with findings, timeline, evidence hashes, and optional assistant summary.";
    case "library":
      return "Browse detection patterns, why they matter, what evidence to look for, MITRE context, false positives, and next analyst steps.";
    case "settings":
      return "Control local AI availability, prompt preview, model defaults, and bounded evidence limits.";
    case "upload":
      return "Upload auth, web, JSON, CSV, syslog, Zeek, or Suricata logs. TraceHawk runs transparent rules, maps findings to MITRE, and keeps evidence visible.";
  }
}

createRoot(document.getElementById("root")!).render(<App />);
