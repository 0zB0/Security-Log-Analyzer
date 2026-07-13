import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
  ListChecks,
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
  PublicDemoStatus,
  analyzePublicDemo,
  analyzePublicSample,
  analyzeCaseBundle,
  analyzeDemo,
  analyzeRealLabCase,
  analyzeSample,
  analyzeUpload,
  getAssistantStatus,
  getAuthStatus,
  getPublicDemoStatus,
} from "../lib/api";
import {
  LiveMonitor,
  MetricGrid,
  WorkspaceBody,
  snapshotToAnalysisResult,
} from "../features/workspace/WorkspaceBody";
import { SAMPLE_OPTIONS } from "./workspaceOptions";
import { ReportFormat, WorkspaceView } from "./workspaceTypes";
import {
  ContextHelpButton,
  GuidedTour,
  TutorialPage,
} from "../features/tutorial/TutorialExperience";
import type { PublicTutorialView } from "../features/tutorial/tutorialRegistry";
import "../styles/main.css";

export function App() {
  const [activeView, setActiveView] = useState<WorkspaceView>(initialWorkspaceView);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [assistantResponse, setAssistantResponse] = useState<AssistantResponse | null>(null);
  const [assistantStatus, setAssistantStatus] = useState<AssistantStatus | null>(null);
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [publicDemoStatus, setPublicDemoStatus] = useState<PublicDemoStatus | null>(null);
  const [runtimeProfileError, setRuntimeProfileError] = useState<string | null>(null);
  const [reportResponse, setReportResponse] = useState<ReportResponse | null>(null);
  const [reportFormat, setReportFormat] = useState<ReportFormat>("markdown");
  const [sampleId, setSampleId] = useState(SAMPLE_OPTIONS[0].id);
  const [libraryRuleId, setLibraryRuleId] = useState<string | null>(null);
  const [latestLiveSnapshot, setLatestLiveSnapshot] = useState<LiveSnapshot | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [, setSessionExpiresAt] = useState<number | null>(null);
  const [sessionRemainingSeconds, setSessionRemainingSeconds] = useState(0);
  const [tourView, setTourView] = useState<PublicTutorialView | null>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const isPublicDemo = publicDemoStatus?.enabled === true;
  const isAdmin =
    !isPublicDemo && (authStatus?.role === "admin" || authStatus?.local_admin === true);

  const navigateToView = useCallback((view: WorkspaceView) => {
    setActiveView(view);
    const path = view === "tutorial" ? "/tutorial" : "/";
    if (window.location.pathname !== path) {
      window.history.pushState({ view }, "", path);
    }
  }, []);

  const clearPublicSession = useCallback(() => {
    setResult(null);
    setSelectedIncidentId(null);
    setSelectedFindingId(null);
    setAssistantResponse(null);
    setReportResponse(null);
    setSearchQuery("");
    setError(null);
    setSessionExpiresAt(null);
    setSessionRemainingSeconds(0);
    navigateToView("upload");
  }, [navigateToView]);
  const closeTour = useCallback(() => setTourView(null), []);

  const acceptAnalysis = useCallback(
    (analysis: AnalysisResult, view: WorkspaceView) => {
      setResult(analysis);
      setSelectedIncidentId(analysis.incidents[0]?.id ?? null);
      setSelectedFindingId(analysis.findings[0]?.id ?? null);
      setReportResponse(null);
      navigateToView(view);
      if (publicDemoStatus?.enabled) {
        setSessionExpiresAt(Date.now() + publicDemoStatus.session_timeout_seconds * 1000);
      }
    },
    [navigateToView, publicDemoStatus],
  );

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
    getPublicDemoStatus()
      .then(async (status) => {
        if (!isMounted) return;
        setRuntimeProfileError(null);
        setPublicDemoStatus(status);
        if (status.enabled) {
          setAuthStatus(null);
          setAssistantStatus(disabledAssistantStatus("Disabled in public demo"));
          return;
        }
        const [auth, assistant] = await Promise.allSettled([
          getAuthStatus(),
          getAssistantStatus(),
        ]);
        if (!isMounted) return;
        setAuthStatus(auth.status === "fulfilled" ? auth.value : null);
        setAssistantStatus(
          assistant.status === "fulfilled"
            ? assistant.value
            : disabledAssistantStatus("Assistant API unavailable"),
        );
      })
      .catch(() => {
        if (isMounted) {
          setRuntimeProfileError("The runtime capability profile could not be verified.");
          setPublicDemoStatus(null);
          setAuthStatus(null);
          setAssistantStatus(disabledAssistantStatus("Application status unavailable"));
        }
      });
    return () => {
      isMounted = false;
    };
  }, []);

  useEffect(() => {
    function handleHistoryNavigation() {
      setActiveView(initialWorkspaceView());
    }
    window.addEventListener("popstate", handleHistoryNavigation);
    return () => window.removeEventListener("popstate", handleHistoryNavigation);
  }, []);

  useEffect(() => {
    if (publicDemoStatus && !publicDemoStatus.enabled && activeView === "tutorial") {
      navigateToView("upload");
    }
  }, [activeView, navigateToView, publicDemoStatus]);

  useEffect(() => {
    if (!isPublicDemo || !result || !publicDemoStatus) {
      return;
    }
    const timeoutMs = publicDemoStatus.session_timeout_seconds * 1000;
    function refreshActivityDeadline() {
      setSessionExpiresAt(Date.now() + timeoutMs);
    }
    window.addEventListener("pointerdown", refreshActivityDeadline);
    window.addEventListener("keydown", refreshActivityDeadline);
    const interval = window.setInterval(() => {
      setSessionExpiresAt((current) => {
        if (current === null) return null;
        const remaining = Math.max(0, Math.ceil((current - Date.now()) / 1000));
        setSessionRemainingSeconds(remaining);
        if (remaining === 0) {
          clearPublicSession();
          return null;
        }
        return current;
      });
    }, 1000);
    return () => {
      window.removeEventListener("pointerdown", refreshActivityDeadline);
      window.removeEventListener("keydown", refreshActivityDeadline);
      window.clearInterval(interval);
    };
  }, [clearPublicSession, isPublicDemo, publicDemoStatus, result]);

  useEffect(() => {
    function handleWorkspaceShortcut(event: KeyboardEvent) {
      const target = event.target;
      const isEditable =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement ||
        (target instanceof HTMLElement && target.isContentEditable);

      if (event.key === "/" && !isEditable) {
        event.preventDefault();
        searchInputRef.current?.focus();
      }
      if (event.key === "Escape" && document.activeElement === searchInputRef.current) {
        setSearchQuery("");
        searchInputRef.current?.blur();
      }
    }

    window.addEventListener("keydown", handleWorkspaceShortcut);
    return () => window.removeEventListener("keydown", handleWorkspaceShortcut);
  }, []);

  async function handleFileChange(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    setIsAnalyzing(true);
    setError(null);
    try {
      if (
        isPublicDemo &&
        publicDemoStatus &&
        file.size > publicDemoStatus.max_bytes
      ) {
        throw new Error(
          `Public demo files are limited to ${publicDemoStatus.max_bytes} bytes.`,
        );
      }
      const analysis = isPublicDemo
        ? (await analyzePublicDemo(file)).analysis
        : await analyzeUpload(file);
      acceptAnalysis(analysis, "incidents");
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
      const analysis = isPublicDemo
        ? (await analyzePublicSample("auth-ssh-compromise")).analysis
        : await analyzeDemo();
      acceptAnalysis(analysis, "incidents");
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
      const analysis = isPublicDemo
        ? (await analyzePublicSample(sampleId)).analysis
        : await analyzeSample(sampleId);
      acceptAnalysis(analysis, "incidents");
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
      acceptAnalysis(analysis, "case");
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
      acceptAnalysis(analysis, "case");
    } catch (caught) {
      setResult(null);
      setSelectedIncidentId(null);
      setSelectedFindingId(null);
      setError(caught instanceof Error ? caught.message : "Real lab case analysis failed");
    } finally {
      setIsAnalyzing(false);
    }
  }

  if (publicDemoStatus === null) {
    return (
      <main className="shell runtime-profile-loading" aria-live="polite">
        <section className="surface">
          <h1>{runtimeProfileError ? "TraceHawk unavailable" : "Loading TraceHawk"}</h1>
          <p>
            {runtimeProfileError ??
              "Resolving the runtime capability profile before enabling the workspace."}
          </p>
        </section>
      </main>
    );
  }

  return (
    <main className="shell">
      <section className="topbar">
        <div className="brand">
          <span className="breadcrumb">SOC / Log Analyzer /</span>
          <strong>{viewTitle(activeView)}</strong>
          <span className="version-pill">
            <span className="status-dot" />
            TraceHawk v0.10.0
          </span>
        </div>
        <div className="topbar-actions">
          <span className="demo-label">
            {isPublicDemo ? "Public session-only demo" : authLabel(authStatus)}
          </span>
          {!isPublicDemo && authStatus?.allowlist_enabled ? (
            <div className="auth-links">
              {!authStatus.authenticated ? (
                <a href="/.auth/login/google?post_login_redirect_uri=%2F">Login</a>
              ) : null}
              {authStatus.authenticated ? (
                <a href="/.auth/logout?post_logout_redirect_uri=%2F">Logout</a>
              ) : null}
            </div>
          ) : null}
          {!isPublicDemo ? <div className={`status ${assistantStatus?.enabled ? "" : "muted"}`}>
            {assistantStatus
              ? `${assistantStatus.provider.toUpperCase()} ${
                  assistantStatus.enabled ? "READY" : "UNAVAILABLE"
                }`
              : "AI STATUS"}
          </div> : null}
        </div>
      </section>
      <section className="commandbar">
        <label className="search-box" data-tour="global-search">
          <Search size={16} />
          <input
            ref={searchInputRef}
            aria-label="Global investigation search"
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            placeholder="Search findings, IPs, users, rules"
          />
        </label>
        <span className="toolbar-button">Data tier: Evidence</span>
        <span className="toolbar-button">Last 24 hours</span>
        {isPublicDemo ? (
          <button
            className="toolbar-button primary"
            onClick={clearPublicSession}
            data-tour="clear-session-top"
          >
            Clear session
          </button>
        ) : (
          <button className="toolbar-button primary" onClick={() => window.location.reload()}>
            Refresh
          </button>
        )}
      </section>
      <section className="workspace">
        <aside className="sidebar">
          <button
            className={activeView === "upload" ? "nav-active" : ""}
            onClick={() => navigateToView("upload")}
            data-tour="nav-upload"
          >
            <FileUp size={16} /> Upload
          </button>
          {!isPublicDemo ? <button
            className={activeView === "case" ? "nav-active" : ""}
            onClick={() => navigateToView("case")}
          >
            <Network size={16} /> Case
          </button> : null}
          {isAdmin ? (
            <button
              className={activeView === "live" ? "nav-active" : ""}
              onClick={() => navigateToView("live")}
            >
              <RadioTower size={16} /> Live Monitor
            </button>
          ) : null}
          <button
            className={activeView === "entities" ? "nav-active" : ""}
            onClick={() => navigateToView("entities")}
            data-tour="nav-entities"
          >
            <Fingerprint size={16} /> Entities
          </button>
          <button
            className={activeView === "mitre" ? "nav-active" : ""}
            onClick={() => navigateToView("mitre")}
            data-tour="nav-mitre"
          >
            <Activity size={16} /> MITRE
          </button>
          <button
            className={activeView === "incidents" ? "nav-active" : ""}
            onClick={() => navigateToView("incidents")}
            data-tour="nav-incidents"
          >
            <AlertTriangle size={16} /> Incidents
          </button>
          {isPublicDemo ? (
            <button
              className={activeView === "findings" ? "nav-active" : ""}
              onClick={() => navigateToView("findings")}
              data-tour="nav-findings"
            >
              <ListChecks size={16} /> Findings
            </button>
          ) : null}
          <button
            className={activeView === "evidence" ? "nav-active" : ""}
            onClick={() => navigateToView("evidence")}
            data-tour="nav-evidence"
          >
            <FileSearch size={16} /> Evidence
          </button>
          {!isPublicDemo ? <button
            className={activeView === "assistant" ? "nav-active" : ""}
            onClick={() => navigateToView("assistant")}
          >
            <BrainCircuit size={16} /> Local AI
          </button> : null}
          <button
            className={activeView === "reports" ? "nav-active" : ""}
            onClick={() => navigateToView("reports")}
            data-tour="nav-reports"
          >
            <ScrollText size={16} /> Reports
          </button>
          <button
            className={activeView === "library" ? "nav-active" : ""}
            onClick={() => navigateToView("library")}
            data-tour="nav-library"
          >
            <BookOpen size={16} /> Library
          </button>
          {isPublicDemo ? (
            <button
              className={activeView === "tutorial" ? "nav-active" : ""}
              onClick={() => navigateToView("tutorial")}
            >
              <BookOpen size={16} /> Tutorial
            </button>
          ) : null}
          {isAdmin ? (
            <button
              className={activeView === "settings" ? "nav-active" : ""}
              onClick={() => navigateToView("settings")}
            >
              <SlidersHorizontal size={16} /> Settings
            </button>
          ) : null}
        </aside>
        <section className="panel investigation">
          {isPublicDemo ? (
            <section className="public-session-banner" data-tour="session-privacy">
              <div>
                <strong>Session-only processing</strong>
                <span>
                  Logs are processed in request memory, are not stored, and are never sent to
                  external AI. Refresh or close this tab to erase the result.
                </span>
              </div>
              <div className="session-banner-actions">
                <span>
                  {result && sessionRemainingSeconds > 0
                    ? `Auto-clear in ${formatDuration(sessionRemainingSeconds)}`
                    : "No active result"}
                </span>
                <button
                  type="button"
                  className="stop-button"
                  onClick={clearPublicSession}
                  data-tour="clear-session-banner"
                >
                  Clear session
                </button>
              </div>
            </section>
          ) : null}
          <section className="intake-strip" data-tour="upload-intake">
            <div className="intake-title">[Investigation intake]</div>
            <div className="intake-subtle">
              {result ? `${result.raw_line_count} lines loaded` : "No file selected"}
            </div>
            <div className="intake-controls">
              <label className="file-inline" data-tour="upload-file">
                <span>Browse...</span>
                <input
                  type="file"
                  accept={
                    publicDemoStatus?.enabled
                      ? publicDemoStatus.allowed_extensions.join(",")
                      : ".log,.txt,.csv,.json,.jsonl,text/plain,application/json"
                  }
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
                data-tour="upload-demo"
              >
                Run demo
              </button>
              <select
                aria-label="Sample scenario"
                className="sample-select"
                value={sampleId}
                onChange={(event) => setSampleId(event.target.value)}
                disabled={isAnalyzing}
                data-tour="upload-samples"
              >
                {SAMPLE_OPTIONS.filter(
                  (sample) =>
                    !isPublicDemo ||
                    ["auth-ssh-compromise", "suricata-alert-burst", "zeek-port-scan"].includes(
                      sample.id,
                    ),
                ).map((sample) => (
                  <option key={sample.id} value={sample.id}>
                    {sample.label}
                  </option>
                ))}
              </select>
              <button
                className="stop-button"
                onClick={handleRunSample}
                disabled={isAnalyzing}
                data-tour="upload-run-sample"
              >
                Run sample
              </button>
              {!isPublicDemo ? <label className="file-inline">
                <span>Case...</span>
                <input
                  type="file"
                  multiple
                  accept=".log,.txt,.csv,.json,.jsonl,text/plain,application/json"
                  onChange={handleCaseBundleChange}
                  disabled={isAnalyzing}
                />
              </label> : null}
              {!isPublicDemo ? <button
                className="stop-button"
                onClick={handleRunRealLabCase}
                disabled={isAnalyzing}
              >
                Real lab case
              </button> : null}
              <button
                className="stop-button"
                data-tour="upload-markdown"
                onClick={() => {
                  setReportFormat("markdown");
                  navigateToView("reports");
                }}
              >
                Markdown
              </button>
              {!isPublicDemo ? <button
                className="stop-button"
                onClick={() => {
                  setReportFormat("pdf");
                  navigateToView("reports");
                }}
              >
                PDF
              </button> : null}
            </div>
          </section>
          <header className="panel-header" data-tour={`view-${activeView}-header`}>
            <div>
              <h1>{viewTitle(activeView)}</h1>
              <p>{viewDescription(activeView)}</p>
            </div>
            {isPublicDemo && activeView !== "tutorial" ? (
              <ContextHelpButton
                view={activeView}
                onStart={(view) => setTourView(view)}
              />
            ) : null}
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

          {activeView !== "library" && activeView !== "tutorial" ? (
            <MetricGrid result={result} isAnalyzing={isAnalyzing} />
          ) : null}

          {activeView === "tutorial" ? (
            <TutorialPage onStart={(view) => setTourView(view)} />
          ) : (
          <div data-tour={`view-${activeView}-content`}>
          <WorkspaceBody
            activeView={activeView}
            result={result}
            selectedIncident={selectedIncident}
            selectedFinding={selectedFinding}
            evidenceForFinding={evidenceForFinding}
            searchQuery={searchQuery}
            assistantResponse={assistantResponse}
            assistantStatus={assistantStatus}
            reportFormat={reportFormat}
            onAssistantResponse={setAssistantResponse}
            reportResponse={reportResponse}
            onReportResponse={setReportResponse}
            onReportFormatChange={setReportFormat}
            publicDemo={isPublicDemo}
            selectedRuleId={libraryRuleId}
            onSelectRule={(ruleId) => {
              setLibraryRuleId(ruleId);
              navigateToView("library");
            }}
            onSelectIncident={(incident) => {
              setSelectedIncidentId(incident.id);
              setSelectedFindingId(incident.finding_ids[0] ?? null);
            }}
            onSelectFinding={setSelectedFindingId}
          />
          </div>
          )}
        </section>
      </section>
      {tourView ? (
        <GuidedTour
          initialView={tourView}
          onNavigate={navigateToView}
          onClose={closeTour}
        />
      ) : null}
    </main>
  );
}

function authLabel(status: AuthStatus | null): string {
  if (!status) {
    return "Auth status unavailable";
  }
  if (status.local_admin || status.auth_mode === "disabled") {
    return "Local admin mode";
  }
  if (status.allowed && status.email) {
    return `Signed in: ${status.email} (${status.role ?? "viewer"})`;
  }
  if (status.authenticated && status.email) {
    return `Account denied: ${status.email}`;
  }
  return "Sign in required";
}

function initialWorkspaceView(): WorkspaceView {
  return window.location.pathname === "/tutorial" ? "tutorial" : "upload";
}

function disabledAssistantStatus(error: string): AssistantStatus {
  return {
    enabled: false,
    provider: "mock",
    url: "",
    model: null,
    available: false,
    installed_models: [],
    error,
  };
}

function formatDuration(totalSeconds: number): string {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
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
    case "findings":
      return "Findings";
    case "evidence":
      return "Evidence review";
    case "assistant":
      return "Local AI";
    case "reports":
      return "Reports";
    case "library":
      return "Detection library";
    case "tutorial":
      return "Guided tutorial";
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
    case "findings":
      return "Review individual deterministic rule matches, confidence, severity, rationale, MITRE context, and linked evidence.";
    case "evidence":
      return "Inspect the exact raw log lines behind each finding without losing rule, severity, and MITRE context.";
    case "assistant":
      return "Local LLM assistance will explain selected incidents with evidence references when Ollama integration is enabled.";
    case "reports":
      return "Generate local Markdown, HTML, or PDF incident reports with findings, timeline, evidence hashes, and optional assistant summary.";
    case "library":
      return "Browse detection patterns, why they matter, what evidence to look for, MITRE context, false positives, and next analyst steps.";
    case "tutorial":
      return "Learn every public demo view through one evidence-first, step-by-step workflow.";
    case "settings":
      return "Control local AI availability, prompt preview, model defaults, and bounded evidence limits.";
    case "upload":
      return "Upload auth, web, JSON, CSV, syslog, Zeek, or Suricata logs. TraceHawk runs transparent rules, maps findings to MITRE, and keeps evidence visible.";
  }
}

const rootElement = document.getElementById("root");
if (rootElement) {
  createRoot(rootElement).render(<App />);
}
