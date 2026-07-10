import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BookOpen,
  BrainCircuit,
  ClipboardList,
  Clock3,
  FileSearch,
  Fingerprint,
  ListFilter,
  Network,
  Pause,
  Play,
  Save,
  ScrollText,
  Square,
} from "lucide-react";

import {
  AnalysisResult,
  AnalystNote,
  AssistantResponse,
  AssistantSettings,
  AssistantStatus,
  EvidenceLine,
  Finding,
  Incident,
  LiveSnapshot,
  ReportResponse,
  RuleLibraryItem,
  createIncidentNote,
  explainIncident,
  generateCaseReport,
  generateIncidentReport,
  getRuleLibrary,
  getAssistantSettings,
  listIncidentNotes,
  liveFileWebSocketUrl,
  liveInterfaceWebSocketUrl,
  previewAssistantPrompt,
  persistLiveSnapshot,
  updateAssistantSettings,
} from "../../lib/api";
import { CAPTURE_PRESETS } from "../../app/workspaceOptions";
import { ReportFormat, WorkspaceView } from "../../app/workspaceTypes";

export function LiveMonitor({
  initialSnapshot,
  onSnapshot,
  onSaved,
  onError,
}: {
  initialSnapshot: LiveSnapshot | null;
  onSnapshot: (snapshot: LiveSnapshot) => void;
  onSaved: (analysis: AnalysisResult) => void;
  onError: (message: string | null) => void;
}) {
  const [sourceMode, setSourceMode] = useState<"file" | "interface">("file");
  const [capturePreset, setCapturePreset] = useState(CAPTURE_PRESETS[0].id);
  const [path, setPath] = useState("packages/sample-data/auth/ssh-bruteforce.log");
  const [interfaceName, setInterfaceName] = useState("lo");
  const [captureFilter, setCaptureFilter] = useState("tcp and dst portrange 33000-33020");
  const [startAtEnd, setStartAtEnd] = useState(false);
  const [status, setStatus] = useState<"idle" | "connecting" | "connected">("idle");
  const [sourceStatus, setSourceStatus] = useState<"idle" | "active" | "paused" | "error">("idle");
  const [latestSnapshot, setLatestSnapshot] = useState<LiveSnapshot | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    setLatestSnapshot(initialSnapshot);
  }, [initialSnapshot]);

  function connect() {
    socketRef.current?.close();
    setStatus("connecting");
    onError(null);

    const socket =
      sourceMode === "interface"
        ? new WebSocket(liveInterfaceWebSocketUrl(interfaceName, captureFilter))
        : new WebSocket(liveFileWebSocketUrl(path, startAtEnd));
    socketRef.current = socket;

    socket.onopen = () => setStatus("connected");
    socket.onmessage = (event) => {
      const snapshot = JSON.parse(event.data) as LiveSnapshot;
      setSourceStatus(snapshot.status);
      if (snapshot.source_error) {
        onError(snapshot.source_error);
      }
      setLatestSnapshot(snapshot);
      onSnapshot(snapshot);
    };
    socket.onerror = () => {
      onError("Live monitor connection failed. Check that the API can read the file path.");
      setStatus("idle");
    };
    socket.onclose = () => {
      if (socketRef.current === socket) {
        socketRef.current = null;
        setStatus("idle");
        setSourceStatus((current) => (current === "error" ? "error" : "idle"));
      }
    };
  }

  function disconnect() {
    socketRef.current?.close();
    socketRef.current = null;
    setStatus("idle");
    setSourceStatus("idle");
  }

  function sendControl(action: "pause" | "resume") {
    socketRef.current?.send(JSON.stringify({ action }));
  }

  async function saveSnapshot() {
    if (!latestSnapshot) {
      return;
    }
    setIsSaving(true);
    onError(null);
    try {
      const analysis = await persistLiveSnapshot(latestSnapshot);
      onSaved(analysis);
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "Live snapshot save failed");
    } finally {
      setIsSaving(false);
    }
  }

  function applyCapturePreset(presetId: string) {
    const preset = CAPTURE_PRESETS.find((item) => item.id === presetId);
    setCapturePreset(presetId);
    if (!preset) {
      return;
    }
    setInterfaceName(preset.interfaceName);
    setCaptureFilter(preset.captureFilter);
  }

  return (
    <>
      <section className="live-control">
      <div className="live-source-mode">
        <label>Source</label>
        <div className="segmented-control">
          <button
            className={sourceMode === "file" ? "selected" : ""}
            onClick={() => setSourceMode("file")}
            disabled={status === "connected" || status === "connecting"}
          >
            File
          </button>
          <button
            className={sourceMode === "interface" ? "selected" : ""}
            onClick={() => setSourceMode("interface")}
            disabled={status === "connected" || status === "connecting"}
          >
            Interface Capture
          </button>
        </div>
      </div>
      {sourceMode === "interface" ? (
        <>
          <div className="live-path">
            <label htmlFor="capture-preset">Preset</label>
            <select
              id="capture-preset"
              value={capturePreset}
              onChange={(event) => applyCapturePreset(event.target.value)}
              disabled={status === "connected" || status === "connecting"}
            >
              {CAPTURE_PRESETS.map((preset) => (
                <option key={preset.id} value={preset.id}>
                  {preset.label}
                </option>
              ))}
            </select>
          </div>
          <div className="live-path">
            <label htmlFor="live-interface">Interface</label>
            <input
              id="live-interface"
              value={interfaceName}
              onChange={(event) => setInterfaceName(event.target.value)}
              placeholder="lo"
            />
          </div>
          <div className="live-path">
            <label htmlFor="capture-filter">Capture filter</label>
            <input
              id="capture-filter"
              value={captureFilter}
              onChange={(event) => setCaptureFilter(event.target.value)}
              placeholder="ip or ip6"
            />
          </div>
        </>
      ) : (
        <>
          <div className="live-path">
            <label htmlFor="live-path">File path</label>
            <input
              id="live-path"
              value={path}
              onChange={(event) => setPath(event.target.value)}
              placeholder="/var/log/auth.log"
            />
          </div>
          <label className="toggle-row">
            <input
              type="checkbox"
              checked={startAtEnd}
              onChange={(event) => setStartAtEnd(event.target.checked)}
            />
            <span>Only new lines</span>
          </label>
        </>
      )}
      <div className={`source-status source-status-${sourceStatus}`}>{sourceStatus}</div>
      {status === "connected" ? (
        <div className="live-actions">
          {sourceStatus === "paused" ? (
            <button className="stop-button" onClick={() => sendControl("resume")}>
              <Play size={16} /> Resume
            </button>
          ) : (
            <button className="stop-button" onClick={() => sendControl("pause")}>
              <Pause size={16} /> Pause
            </button>
          )}
          <button className="stop-button" onClick={disconnect}>
            <Square size={16} /> Stop
          </button>
          <button
            className="stop-button"
            onClick={saveSnapshot}
            disabled={!latestSnapshot?.evidence.length || isSaving}
          >
            <Save size={16} /> {isSaving ? "Saving" : "Save"}
          </button>
        </div>
      ) : (
        <div className="live-actions">
          <button
            className="upload-button"
            onClick={connect}
            disabled={
              status === "connecting" || (sourceMode === "interface" ? !interfaceName : !path)
            }
          >
            <Play size={16} /> {status === "connecting" ? "Connecting" : "Start"}
          </button>
          <button
            className="stop-button"
            onClick={saveSnapshot}
            disabled={!latestSnapshot?.evidence.length || isSaving}
          >
            <Save size={16} /> {isSaving ? "Saving" : "Save"}
          </button>
        </div>
      )}
      </section>
      <section className="live-snapshot-strip">
        <span>{latestSnapshot ? latestSnapshot.parser ?? "detecting" : "no snapshot"}</span>
        <span>{latestSnapshot?.raw_line_count ?? 0} lines</span>
        <span>{latestSnapshot?.finding_count ?? 0} findings</span>
        <span>{latestSnapshot?.incident_count ?? 0} incidents</span>
        <span>{latestSnapshot?.evidence.length ? "snapshot ready" : "no evidence"}</span>
      </section>
    </>
  );
}

export function snapshotToAnalysisResult(snapshot: LiveSnapshot): AnalysisResult {
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

export function WorkspaceBody({
  activeView,
  result,
  selectedIncident,
  selectedFinding,
  evidenceForFinding,
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
}: {
  activeView: WorkspaceView;
  result: AnalysisResult | null;
  selectedIncident: Incident | null;
  selectedFinding: Finding | null;
  evidenceForFinding: EvidenceLine[];
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
}) {
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
      />
    );
  }

  if (activeView === "library") {
    return <DetectionLibrary result={result} selectedRuleId={selectedRuleId} onSelectRule={onSelectRule} />;
  }

  if (activeView === "entities") {
    return <EntityInventory result={result} onSelectIncident={onSelectIncident} onSelectFinding={onSelectFinding} />;
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

  if (activeView === "case") {
    return <CaseOverview result={result} />;
  }

  if (activeView === "evidence") {
    return (
      <EvidenceReview
        findings={result?.findings ?? []}
        selectedFinding={selectedFinding}
        evidence={evidenceForFinding}
        onSelectFinding={onSelectFinding}
        onOpenRule={onSelectRule}
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
          findings={result?.findings ?? []}
          selectedFinding={selectedFinding}
          onSelect={onSelectFinding}
          onOpenRule={onSelectRule}
          emptyText={
            activeView === "live"
              ? "No findings yet. Start live monitoring or append matching log lines to the watched file."
              : "No findings yet. Upload a supported auth, web, Zeek, Suricata, JSON, CSV, or syslog file to test the rule engine."
          }
        />
        <EvidencePanel finding={selectedFinding} evidence={evidenceForFinding} />
      </section>
    </>
  );
}

function EntityInventory({
  result,
  onSelectIncident,
  onSelectFinding,
}: {
  result: AnalysisResult | null;
  onSelectIncident: (incident: Incident) => void;
  onSelectFinding: (id: string) => void;
}) {
  const incidentsById = new Map((result?.incidents ?? []).map((incident) => [incident.id, incident]));
  const topEntities = [...(result?.entities ?? [])].sort(
    (left, right) => right.risk_score - left.risk_score || right.event_count - left.event_count
  );

  return (
    <section className="surface entity-inventory">
      <div className="surface-header">
        <div>
          <h2>Entity inventory</h2>
          <p>Extracted IPs, users, hosts, services, paths, domains, and containers linked to findings.</p>
        </div>
        <Fingerprint size={18} />
      </div>
      {!result ? (
        <div className="empty-state">Run an analysis to build the entity inventory.</div>
      ) : topEntities.length === 0 ? (
        <div className="empty-state">No entities were extracted from this analysis.</div>
      ) : (
        <div className="entity-grid">
          {topEntities.map((entity) => (
            <article className="entity-card" key={entity.id}>
              <div className="entity-card-top">
                <span className="entity-type">{entity.entity_type}</span>
                <strong>{entity.value}</strong>
                <span className="entity-risk">risk {entity.risk_score}</span>
              </div>
              <div className="entity-stats">
                <span>{entity.event_count} events</span>
                <span>{entity.finding_ids.length} findings</span>
                <span>{entity.incident_ids.length} incidents</span>
              </div>
              <div className="entity-links">
                {entity.incident_ids.slice(0, 3).map((incidentId) => {
                  const incident = incidentsById.get(incidentId);
                  return incident ? (
                    <button key={incidentId} onClick={() => onSelectIncident(incident)}>
                      {incident.title}
                    </button>
                  ) : null;
                })}
                {entity.finding_ids.slice(0, 3).map((findingId) => (
                  <button key={findingId} onClick={() => onSelectFinding(findingId)}>
                    {shortId(findingId)}
                  </button>
                ))}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function MitreMapPanel({
  result,
  onSelectFinding,
}: {
  result: AnalysisResult | null;
  onSelectFinding: (id: string) => void;
}) {
  const groups = buildMitreGroups(result?.findings ?? []);
  return (
    <section className="surface mitre-map">
      <div className="surface-header">
        <div>
          <h2>MITRE map</h2>
          <p>Tactics and techniques represented by deterministic findings in the current analysis.</p>
        </div>
        <Activity size={18} />
      </div>
      {!result ? (
        <div className="empty-state">Run an analysis to build the MITRE map.</div>
      ) : groups.length === 0 ? (
        <div className="empty-state">No MITRE mappings were found.</div>
      ) : (
        <div className="mitre-grid">
          {groups.map((group) => (
            <article className="mitre-tactic" key={group.tactic}>
              <div className="mitre-tactic-header">
                <h3>{group.tactic}</h3>
                <span>{group.findingCount} findings</span>
              </div>
              <div className="mitre-technique-list">
                {group.techniques.map((technique) => (
                  <div className="mitre-technique" key={`${group.tactic}-${technique.techniqueId ?? "unmapped"}`}>
                    <div className="mitre-technique-title">
                      <strong>{technique.techniqueId ?? "Unmapped"}</strong>
                      <SeverityBadge severity={technique.maxSeverity} />
                    </div>
                    <p>{technique.techniqueName ?? "No confident MITRE technique mapping."}</p>
                    <div className="finding-meta">
                      <span>{technique.ruleIds.length} rules</span>
                      <span>{technique.evidenceCount} evidence lines</span>
                    </div>
                    <div className="entity-links">
                      {technique.findingIds.slice(0, 4).map((findingId) => (
                        <button key={findingId} onClick={() => onSelectFinding(findingId)}>
                          {shortId(findingId)}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function buildMitreGroups(findings: Finding[]): {
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
}[] {
  const tacticMap = new Map<string, Map<string, {
    techniqueId: string | null;
    techniqueName: string | null;
    maxSeverity: Finding["severity"];
    ruleIds: Set<string>;
    findingIds: string[];
    evidenceIds: Set<string>;
  }>>();
  for (const finding of findings) {
    const tactic = finding.mitre.tactic ?? "Unmapped";
    const techniqueKey = finding.mitre.technique_id ?? "unmapped";
    const techniques = tacticMap.get(tactic) ?? new Map();
    const current =
      techniques.get(techniqueKey) ??
      {
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
      findingCount: Array.from(techniques.values()).reduce((total, item) => total + item.findingIds.length, 0),
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

function higherSeverity(left: Finding["severity"], right: Finding["severity"]): Finding["severity"] {
  const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return rank[right] > rank[left] ? right : left;
}

function DetectionLibrary({
  result,
  selectedRuleId,
  onSelectRule,
}: {
  result: AnalysisResult | null;
  selectedRuleId: string | null;
  onSelectRule: (ruleId: string) => void;
}) {
  const [rules, setRules] = useState<RuleLibraryItem[]>([]);
  const [localSelectedRuleId, setLocalSelectedRuleId] = useState<string | null>(null);
  const [category, setCategory] = useState("all");
  const [query, setQuery] = useState("");
  const [foundOnly, setFoundOnly] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const matchedRuleIds = useMemo(
    () => new Set((result?.findings ?? []).map((finding) => finding.rule_id)),
    [result],
  );
  const activeRuleId = selectedRuleId ?? localSelectedRuleId;

  useEffect(() => {
    let isMounted = true;
    getRuleLibrary()
      .then((library) => {
        if (!isMounted) {
          return;
        }
        setRules(library.rules);
        setLocalSelectedRuleId((current) => current ?? library.rules[0]?.id ?? null);
      })
      .catch((caught) => {
        if (isMounted) {
          setError(caught instanceof Error ? caught.message : "Rule library failed");
        }
      });
    return () => {
      isMounted = false;
    };
  }, []);

  const categories = useMemo(() => ["all", ...Array.from(new Set(rules.map((rule) => rule.category)))], [rules]);
  const filteredRules = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return rules.filter((rule) => {
      if (category !== "all" && rule.category !== category) {
        return false;
      }
      if (foundOnly && !matchedRuleIds.has(rule.id)) {
        return false;
      }
      if (!normalizedQuery) {
        return true;
      }
      return [
        rule.id,
        rule.title,
        rule.description,
        rule.mitre_tactic,
        rule.mitre_technique_id,
        rule.mitre_technique_name,
        ...rule.log_types,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(normalizedQuery));
    });
  }, [category, foundOnly, matchedRuleIds, query, rules]);
  const selectedRule =
    filteredRules.find((rule) => rule.id === activeRuleId) ??
    rules.find((rule) => rule.id === activeRuleId) ??
    filteredRules[0] ??
    rules[0] ??
    null;
  const relatedFindings = useMemo(
    () => (selectedRule ? (result?.findings ?? []).filter((finding) => finding.rule_id === selectedRule.id) : []),
    [result, selectedRule],
  );

  return (
    <section className="library-workbench">
      <section className="surface library-list-surface">
        <div className="surface-header">
          <div>
            <h2>Patterns</h2>
            <p>{filteredRules.length} visible rules from the deterministic rule engine.</p>
          </div>
          <BookOpen size={18} />
        </div>
        <div className="library-controls">
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search rule, MITRE, log type"
          />
          <select value={category} onChange={(event) => setCategory(event.target.value)}>
            {categories.map((item) => (
              <option key={item} value={item}>
                {item === "all" ? "All categories" : item}
              </option>
            ))}
          </select>
          <label className="toggle-row library-toggle">
            <input
              type="checkbox"
              checked={foundOnly}
              onChange={(event) => setFoundOnly(event.target.checked)}
              disabled={!matchedRuleIds.size}
            />
            <span>Found only</span>
          </label>
        </div>
        {error ? <div className="error-banner">{error}</div> : null}
        <div className="library-rule-list">
          {filteredRules.map((rule) => (
            <button
              className={`library-rule-row ${selectedRule?.id === rule.id ? "selected" : ""}`}
              key={rule.id}
              onClick={() => {
                setLocalSelectedRuleId(rule.id);
                onSelectRule(rule.id);
              }}
            >
              <div className="finding-title-row">
                <strong>{rule.title}</strong>
                <SeverityBadge severity={rule.severity} />
              </div>
              <p>{rule.description}</p>
              <div className="finding-meta">
                <span>{rule.category}</span>
                <span>{rule.confidence} confidence</span>
                {rule.mitre_technique_id ? <span>{rule.mitre_technique_id}</span> : null}
                {matchedRuleIds.has(rule.id) ? <span className="active-match">found in current case</span> : null}
              </div>
            </button>
          ))}
        </div>
      </section>
      <RuleLibraryDetail
        rule={selectedRule}
        matched={selectedRule ? matchedRuleIds.has(selectedRule.id) : false}
        relatedFindings={relatedFindings}
      />
    </section>
  );
}

function RuleLibraryDetail({
  rule,
  matched,
  relatedFindings,
}: {
  rule: RuleLibraryItem | null;
  matched: boolean;
  relatedFindings: Finding[];
}) {
  if (!rule) {
    return (
      <section className="surface library-detail-surface">
        <div className="empty-state">No rule selected.</div>
      </section>
    );
  }

  return (
    <section className="surface library-detail-surface">
      <div className="surface-header">
        <div>
          <h2>{rule.title}</h2>
          <p>{rule.danger_summary}</p>
        </div>
        <SeverityBadge severity={rule.severity} />
      </div>
      <div className="library-detail-body">
        <div className="detail-grid">
          <span>Rule ID</span>
          <strong>{rule.id}</strong>
          <span>Category</span>
          <strong>{rule.category}</strong>
          <span>Confidence</span>
          <strong>{rule.confidence}</strong>
          <span>Log types</span>
          <strong>{rule.log_types.join(", ")}</strong>
          <span>MITRE</span>
          <strong>
            {rule.mitre_technique_id
              ? `${rule.mitre_technique_id} ${rule.mitre_technique_name ?? ""}`
              : "Not mapped"}
          </strong>
          <span>Current case</span>
          <strong>{matched ? "Detected" : "Not detected"}</strong>
        </div>
      </div>
      <RuleLearningSection title="Why it matters" items={[rule.description, rule.danger_summary]} />
      <RuleLearningSection title="What TraceHawk looks for" items={rule.look_for} />
      <RuleLearningSection
        title="Current findings"
        items={relatedFindings.map(
          (finding) => `${finding.title}: ${finding.event_count} event(s), ${finding.confidence} confidence`,
        )}
      />
      <RuleLearningSection title="False positives" items={rule.false_positives} />
      <RuleLearningSection title="Analyst next steps" items={rule.recommendations} />
    </section>
  );
}

function RuleLearningSection({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="library-learning-section">
      <h3>{title}</h3>
      {items.length === 0 ? (
        <div className="empty-state compact-empty">No notes recorded.</div>
      ) : (
        <ul>
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

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

function CaseOverview({ result }: { result: AnalysisResult | null }) {
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

function groupCrossSourceLinks(links: AnalysisResult["cross_source_links"]) {
  const groups = new Map<string, AnalysisResult["cross_source_links"]>();
  for (const link of links) {
    const group = groups.get(link.link_type) ?? [];
    group.push(link);
    groups.set(link.link_type, group);
  }
  return Array.from(groups.entries())
    .map(([type, groupLinks]) => ({ type, links: groupLinks }))
    .sort((left, right) => right.links.length - left.links.length || left.type.localeCompare(right.type));
}

function linkGroupLabel(type: string): string {
  if (type === "http_path_match") {
    return "HTTP path matches";
  }
  if (type === "dns_query_match") {
    return "DNS query matches";
  }
  if (type === "flow_match") {
    return "Flow matches";
  }
  return type;
}

function buildCaseMetrics(result: AnalysisResult): { label: string; value: string }[] {
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

type CaseTimelineItem = {
  id: string;
  timestamp: string | null;
  kind: "event" | "link";
  source: string;
  summary: string;
  detail: string;
};

function buildCaseTimeline(result: AnalysisResult, selectedSourceId: string): CaseTimelineItem[] {
  const sourceById = new Map(result.sources.map((source) => [source.source_id, source.filename]));
  const sourceFilter =
    selectedSourceId === "all" ? null : result.sources.find((source) => source.source_id === selectedSourceId);
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
      const leftTime = left.timestamp ? new Date(left.timestamp).getTime() : Number.MAX_SAFE_INTEGER;
      const rightTime = right.timestamp ? new Date(right.timestamp).getTime() : Number.MAX_SAFE_INTEGER;
      const kindOrder = left.kind === right.kind ? 0 : left.kind === "event" ? -1 : 1;
      return leftTime - rightTime || kindOrder || left.id.localeCompare(right.id);
    })
    .slice(0, 80);
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

function stringValue(value: unknown): string | null {
  return value === null || value === undefined || value === "" ? null : String(value);
}

function shortId(value: string): string {
  return value.length > 24 ? `${value.slice(0, 24)}...` : value;
}

function IncidentOverview({
  incidents,
  selectedIncident,
  onSelectIncident,
}: {
  incidents: Incident[];
  selectedIncident: Incident | null;
  onSelectIncident: (incident: Incident) => void;
}) {
  return (
    <section className="surface incident-surface">
      <div className="surface-header compact">
        <div>
          <h2>Incidents</h2>
          <p>Correlated findings grouped by shared entities and time context.</p>
        </div>
        <AlertTriangle size={18} />
      </div>

      {incidents.length === 0 ? (
        <div className="empty-state">No incidents yet. Findings will be grouped here.</div>
      ) : (
        <div className="incident-list">
          {incidents.map((incident) => (
            <button
              className={`incident-item ${selectedIncident?.id === incident.id ? "selected" : ""}`}
              key={incident.id}
              onClick={() => onSelectIncident(incident)}
            >
              <div className="incident-main">
                <div className="finding-title-row">
                  <strong>{incident.title}</strong>
                  <SeverityBadge severity={incident.severity} />
                </div>
                <p>{incident.summary}</p>
                <div className="finding-meta">
                  <span>score {incident.score}</span>
                  <span>{incident.finding_ids.length} findings</span>
                  <span>{incident.timeline.length} timeline events</span>
                  {incident.mitre_techniques.map((technique) => (
                    <span key={technique}>{technique}</span>
                  ))}
                </div>
              </div>
              <div className="entity-list">
                {incident.entities.slice(0, 6).map((entity) => (
                  <span key={entity}>{entity}</span>
                ))}
              </div>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}

function IncidentDetail({
  analysisId,
  incident,
  findings,
  onSelectFinding,
}: {
  analysisId: string | null;
  incident: Incident | null;
  findings: Finding[];
  onSelectFinding: (id: string) => void;
}) {
  const [notes, setNotes] = useState<AnalystNote[]>([]);
  const [noteBody, setNoteBody] = useState("");
  const [noteType, setNoteType] = useState<AnalystNote["note_type"]>("observation");
  const [noteError, setNoteError] = useState<string | null>(null);
  const [isSavingNote, setIsSavingNote] = useState(false);

  useEffect(() => {
    let isMounted = true;
    setNotes([]);
    setNoteError(null);
    if (!analysisId || !incident) {
      return () => {
        isMounted = false;
      };
    }
    listIncidentNotes(analysisId, incident.id)
      .then((items) => {
        if (isMounted) {
          setNotes(items);
        }
      })
      .catch((caught) => {
        if (isMounted) {
          setNoteError(caught instanceof Error ? caught.message : "Note lookup failed");
        }
      });
    return () => {
      isMounted = false;
    };
  }, [analysisId, incident]);

  async function handleCreateNote() {
    if (!analysisId || !incident || !noteBody.trim()) {
      return;
    }
    setIsSavingNote(true);
    setNoteError(null);
    try {
      const note = await createIncidentNote({
        analysis_id: analysisId,
        incident_id: incident.id,
        body: noteBody,
        note_type: noteType,
      });
      setNotes((current) => [note, ...current]);
      setNoteBody("");
      setNoteType("observation");
    } catch (caught) {
      setNoteError(caught instanceof Error ? caught.message : "Note creation failed");
    } finally {
      setIsSavingNote(false);
    }
  }

  if (!incident) {
    return (
      <section className="surface incident-detail">
        <div className="surface-header">
          <div>
            <h2>Incident detail</h2>
            <p>Select an incident to inspect timeline, entities, and linked findings.</p>
          </div>
          <Clock3 size={18} />
        </div>
        <div className="empty-state">No incident selected.</div>
      </section>
    );
  }

  const linkedFindings = incident.finding_ids
    .map((id) => findings.find((finding) => finding.id === id))
    .filter((finding): finding is Finding => Boolean(finding));

  return (
    <section className="surface incident-detail">
      <div className="surface-header">
        <div>
          <h2>{incident.title}</h2>
          <p>{incident.summary}</p>
        </div>
        <SeverityBadge severity={incident.severity} />
      </div>
      <div className="incident-detail-body">
        <div className="detail-grid incident-stats">
          <span>Score</span>
          <strong>{incident.score}</strong>
          <span>Status</span>
          <strong>{incident.status}</strong>
          <span>Findings</span>
          <strong>{incident.finding_ids.length}</strong>
          <span>Window</span>
          <strong>{formatTimeRange(incident.first_seen, incident.last_seen)}</strong>
        </div>
        <div className="finding-meta">
          {incident.mitre_techniques.map((technique) => (
            <span key={technique}>{technique}</span>
          ))}
          {incident.entities.map((entity) => (
            <span key={entity}>{entity}</span>
          ))}
        </div>
      </div>
      <ScoreBreakdownPanel incident={incident} />
      <AnalystNotesPanel
        notes={notes}
        body={noteBody}
        noteType={noteType}
        error={noteError}
        disabled={!analysisId || isSavingNote}
        onBodyChange={setNoteBody}
        onTypeChange={setNoteType}
        onCreate={handleCreateNote}
      />
      <div className="linked-findings">
        <h3>Linked findings</h3>
        {linkedFindings.map((finding) => (
          <button className="linked-finding" key={finding.id} onClick={() => onSelectFinding(finding.id)}>
            <span>{finding.title}</span>
            <SeverityBadge severity={finding.severity} />
          </button>
        ))}
      </div>
      <TimelinePanel timeline={incident.timeline} />
    </section>
  );
}

function AnalystNotesPanel({
  notes,
  body,
  noteType,
  error,
  disabled,
  onBodyChange,
  onTypeChange,
  onCreate,
}: {
  notes: AnalystNote[];
  body: string;
  noteType: AnalystNote["note_type"];
  error: string | null;
  disabled: boolean;
  onBodyChange: (value: string) => void;
  onTypeChange: (value: AnalystNote["note_type"]) => void;
  onCreate: () => void;
}) {
  return (
    <div className="analyst-notes-panel">
      <div className="surface-header compact">
        <div>
          <h3>Analyst notes</h3>
          <p>Manual observations, decisions, follow-ups, and false-positive calls for this incident.</p>
        </div>
        <ClipboardList size={18} />
      </div>
      <div className="note-compose">
        <select
          value={noteType}
          onChange={(event) => onTypeChange(event.target.value as AnalystNote["note_type"])}
          disabled={disabled}
        >
          <option value="observation">Observation</option>
          <option value="decision">Decision</option>
          <option value="follow_up">Follow-up</option>
          <option value="false_positive">False positive</option>
        </select>
        <textarea
          value={body}
          onChange={(event) => onBodyChange(event.target.value)}
          placeholder="Record the analyst decision or next step"
          disabled={disabled}
        />
        <button className="upload-button" onClick={onCreate} disabled={disabled || !body.trim()}>
          Save note
        </button>
      </div>
      {error ? <div className="error-banner compact-error">{error}</div> : null}
      {notes.length === 0 ? (
        <div className="empty-state compact-empty">No analyst notes recorded.</div>
      ) : (
        <div className="note-list">
          {notes.map((note) => (
            <article className="note-card" key={note.id}>
              <div className="note-card-top">
                <span>{formatScoreComponent(note.note_type)}</span>
                <time>{formatTime(note.created_at)}</time>
              </div>
              <p>{note.body}</p>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}

function ScoreBreakdownPanel({ incident }: { incident: Incident }) {
  const breakdown = Object.entries(incident.score_breakdown ?? {});
  const rationale = incident.score_rationale ?? [];
  if (breakdown.length === 0 && rationale.length === 0) {
    return null;
  }

  return (
    <div className="score-panel">
      <h3>Scoring rationale</h3>
      {breakdown.length ? (
        <div className="score-breakdown-grid">
          {breakdown.map(([key, value]) => (
            <div className="score-breakdown-item" key={key}>
              <span>{formatScoreComponent(key)}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
      ) : null}
      {rationale.length ? (
        <ul className="score-rationale-list">
          {rationale.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function formatScoreComponent(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function TimelinePanel({ timeline }: { timeline: string[] }) {
  return (
    <div className="timeline-panel">
      <h3>Timeline</h3>
      {timeline.length === 0 ? (
        <div className="empty-state compact-empty">No timeline entries.</div>
      ) : (
        <ol className="timeline-list">
          {timeline.map((item, index) => (
            <li key={`${item}-${index}`}>
              <span className="timeline-index">{index + 1}</span>
              <code>{item}</code>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function FindingsPanel({
  findings,
  selectedFinding,
  onSelect,
  onOpenRule,
  emptyText = "No findings available.",
}: {
  findings: Finding[];
  selectedFinding: Finding | null;
  onSelect: (id: string) => void;
  onOpenRule: (ruleId: string) => void;
  emptyText?: string;
}) {
  return (
    <section className="surface">
      <div className="surface-header">
        <div>
          <h2>Findings</h2>
          <p>Rule-based detections with confidence and MITRE context.</p>
        </div>
        <ListFilter size={18} />
      </div>

      {findings.length === 0 ? (
        <div className="empty-state">{emptyText}</div>
      ) : (
        <div className="finding-list">
          {findings.map((finding) => (
            <div
              className={`finding-item ${selectedFinding?.id === finding.id ? "selected" : ""}`}
              key={finding.id}
            >
              <button className="finding-main-button" onClick={() => onSelect(finding.id)}>
                <div className="finding-title-row">
                  <strong>{finding.title}</strong>
                  <SeverityBadge severity={finding.severity} />
                </div>
                <p>{finding.summary}</p>
                <div className="finding-meta">
                  <span>{finding.confidence} confidence</span>
                  <span>{finding.event_count} events</span>
                  {finding.mitre.technique_id ? <span>{finding.mitre.technique_id}</span> : null}
                </div>
              </button>
              <button className="rule-link-button" onClick={() => onOpenRule(finding.rule_id)}>
                <BookOpen size={14} /> Rule
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function SettingsPanel({
  result,
  selectedIncident,
}: {
  result: AnalysisResult | null;
  selectedIncident: Incident | null;
}) {
  const [settings, setSettings] = useState<AssistantSettings | null>(null);
  const [promptPreview, setPromptPreview] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    getAssistantSettings()
      .then((loaded) => {
        if (isMounted) {
          setSettings(loaded);
        }
      })
      .catch((caught) => {
        if (isMounted) {
          setError(caught instanceof Error ? caught.message : "Assistant settings failed");
        }
      });
    return () => {
      isMounted = false;
    };
  }, []);

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
    return Array.from(new Set(linkedFindings.flatMap((finding) => finding.evidence_line_ids)))
      .map((id) => evidenceById.get(id))
      .filter((line): line is EvidenceLine => Boolean(line));
  }, [result, linkedFindings]);

  async function saveSettings(nextSettings: AssistantSettings) {
    setError(null);
    setStatus(null);
    try {
      const saved = await updateAssistantSettings(nextSettings);
      setSettings(saved);
      setStatus("Settings saved");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Assistant settings update failed");
    }
  }

  async function buildPreview() {
    if (!settings || !selectedIncident) {
      return;
    }
    setError(null);
    try {
      const preview = await previewAssistantPrompt({
        incident: selectedIncident,
        findings: linkedFindings,
        evidence: linkedEvidence,
        question: "Explain this incident for a junior analyst.",
        model: settings.default_model,
      });
      setPromptPreview(preview.prompt);
      setStatus(
        `Prompt preview built with ${preview.evidence_line_count} evidence line(s)${
          preview.truncated ? " and truncation" : ""
        }`
      );
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Prompt preview failed");
    }
  }

  async function copyPrompt() {
    if (!promptPreview) {
      return;
    }
    await navigator.clipboard?.writeText(promptPreview);
    setStatus("Prompt copied");
  }

  if (!settings) {
    return (
      <section className="surface settings-panel">
        <div className="empty-state">Loading settings.</div>
      </section>
    );
  }

  return (
    <section className="settings-grid">
      <section className="surface settings-panel">
        <div className="surface-header">
          <div>
            <h2>Local AI settings</h2>
            <p>Control whether the assistant can call a local model and how much evidence enters the prompt.</p>
          </div>
          <BrainCircuit size={18} />
        </div>
        <label className="settings-toggle">
          <input
            type="checkbox"
            checked={settings.ai_enabled}
            onChange={(event) => saveSettings({ ...settings, ai_enabled: event.target.checked })}
          />
          <span>Local AI enabled</span>
        </label>
        <label className="settings-field">
          <span>Default model</span>
          <input
            value={settings.default_model}
            onChange={(event) => setSettings({ ...settings, default_model: event.target.value })}
            onBlur={() => saveSettings(settings)}
          />
        </label>
        <label className="settings-toggle">
          <input
            type="checkbox"
            checked={settings.show_prompt_preview}
            onChange={(event) => saveSettings({ ...settings, show_prompt_preview: event.target.checked })}
          />
          <span>Show prompt preview</span>
        </label>
        <div className="settings-number-grid">
          <label className="settings-field">
            <span>Evidence lines</span>
            <input
              type="number"
              min={1}
              max={100}
              value={settings.max_evidence_lines}
              onChange={(event) =>
                setSettings({ ...settings, max_evidence_lines: Number(event.target.value) })
              }
              onBlur={() => saveSettings(settings)}
            />
          </label>
          <label className="settings-field">
            <span>Evidence chars</span>
            <input
              type="number"
              min={200}
              max={50000}
              value={settings.max_evidence_chars}
              onChange={(event) =>
                setSettings({ ...settings, max_evidence_chars: Number(event.target.value) })
              }
              onBlur={() => saveSettings(settings)}
            />
          </label>
        </div>
        {status ? <div className="success-banner">{status}</div> : null}
        {error ? <div className="error-banner compact-error">{error}</div> : null}
      </section>
      <section className="surface settings-panel">
        <div className="surface-header">
          <div>
            <h2>Prompt preview</h2>
            <p>Preview and copy the exact bounded prompt for the selected incident.</p>
          </div>
          <ClipboardList size={18} />
        </div>
        <div className="settings-actions">
          <button className="upload-button" onClick={buildPreview} disabled={!selectedIncident}>
            Build preview
          </button>
          <button className="stop-button" onClick={copyPrompt} disabled={!promptPreview}>
            Copy prompt
          </button>
        </div>
        {settings.show_prompt_preview ? (
          <pre className="prompt-preview">{promptPreview || "No prompt preview generated."}</pre>
        ) : (
          <div className="empty-state">Prompt preview is hidden by settings.</div>
        )}
      </section>
    </section>
  );
}

function AssistantPanel({
  result,
  selectedIncident,
  response,
  status,
  onResponse,
}: {
  result: AnalysisResult | null;
  selectedIncident: Incident | null;
  response: AssistantResponse | null;
  status: AssistantStatus | null;
  onResponse: (response: AssistantResponse | null) => void;
}) {
  const [question, setQuestion] = useState("Explain this incident for a junior analyst.");
  const [selectedModel, setSelectedModel] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedModel && status?.model) {
      setSelectedModel(status.model);
    }
  }, [selectedModel, status?.model]);

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

  async function handleExplain() {
    if (!selectedIncident) {
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const assistantResult = await explainIncident({
        incident: selectedIncident,
        findings: linkedFindings,
        evidence: linkedEvidence,
        question,
        model: selectedModel || undefined,
      });
      onResponse(assistantResult);
    } catch (caught) {
      onResponse(null);
      setError(caught instanceof Error ? caught.message : "Assistant request failed");
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <section className="assistant-grid">
      <section className="surface assistant-surface">
        <div className="surface-header">
          <div>
            <h2>Local assistant</h2>
            <p>Local-only provider using bounded incident context and evidence references.</p>
          </div>
          <BrainCircuit size={18} />
        </div>
        <div className="assistant-body">
          <div className="detail-grid">
            <span>Selected incident</span>
            <strong>{selectedIncident?.title ?? "None"}</strong>
            <span>Provider</span>
            <strong>{status ? status.provider : "Checking"}</strong>
            <span>Model</span>
            <strong>{selectedModel || status?.model || "None"}</strong>
            <span>Status</span>
            <strong>{status?.enabled ? "Ready" : "Unavailable"}</strong>
            <span>Mode</span>
            <strong>Evidence-referenced explanation</strong>
            <span>Findings</span>
            <strong>{linkedFindings.length}</strong>
            <span>Evidence</span>
            <strong>{linkedEvidence.length} lines</strong>
          </div>
          {status?.error ? <div className="error-banner">{status.error}</div> : null}
          <div className="assistant-question">
            <label htmlFor="assistant-model">Model</label>
            <select
              id="assistant-model"
              value={selectedModel}
              onChange={(event) => setSelectedModel(event.target.value)}
              disabled={!status?.installed_models.length}
            >
              {status?.installed_models.length ? (
                status.installed_models.map((model) => (
                  <option key={model} value={model}>
                    {model}
                  </option>
                ))
              ) : (
                <option value={status?.model ?? ""}>{status?.model ?? "No local model"}</option>
              )}
            </select>
          </div>
          <div className="assistant-question">
            <label htmlFor="assistant-question">Question</label>
            <textarea
              id="assistant-question"
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              rows={3}
            />
          </div>
          {error ? <div className="error-banner">{error}</div> : null}
          <button className="upload-button" onClick={handleExplain} disabled={!selectedIncident || isLoading}>
            <BrainCircuit size={16} /> {isLoading ? "Generating" : "Generate explanation"}
          </button>
        </div>
      </section>
      <section className="surface assistant-output">
      <div className="surface-header">
        <div>
          <h2>Assistant output</h2>
          <p>Generated locally from deterministic findings and bounded evidence.</p>
        </div>
        <BrainCircuit size={18} />
      </div>
        {response ? (
          <div className="assistant-result">
            <div className="detail-grid compact-detail">
              <span>Provider</span>
              <strong>{response.provider}</strong>
              <span>Model</span>
              <strong>{response.model}</strong>
              <span>Mode</span>
              <strong>{response.mode}</strong>
            </div>
            <h3>Summary</h3>
            <p>{response.summary}</p>
            <h3>Key points</h3>
            <ul>
              {response.key_points.map((point) => (
                <li key={point}>{point}</li>
              ))}
            </ul>
            <h3>Recommended next steps</h3>
            <ul>
              {response.recommended_next_steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ul>
            <h3>Guardrails</h3>
            <ul>
              {response.guardrails.map((guardrail) => (
                <li key={guardrail}>{guardrail}</li>
              ))}
            </ul>
            <h3>Prompt preview</h3>
            <pre>{response.prompt}</pre>
          </div>
        ) : (
          <div className="empty-state">Generate an explanation for the selected incident.</div>
        )}
      </section>
    </section>
  );
}

function ReportPanel({
  result,
  selectedIncident,
  assistantResponse,
  reportFormat,
  report,
  onReport,
  onReportFormatChange,
}: {
  result: AnalysisResult | null;
  selectedIncident: Incident | null;
  assistantResponse: AssistantResponse | null;
  reportFormat: ReportFormat;
  report: ReportResponse | null;
  onReport: (report: ReportResponse | null) => void;
  onReportFormatChange: (format: ReportFormat) => void;
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
        ? await generateCaseReport({
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
      <section className="surface report-control">
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
              >
                HTML
              </button>
              <button
                className={reportFormat === "pdf" ? "selected" : ""}
                onClick={() => onReportFormatChange("pdf")}
              >
                PDF
              </button>
            </div>
          </div>
          <label className="toggle-row">
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
            >
              <ScrollText size={16} /> {isGenerating ? "Generating" : "Generate report"}
            </button>
            <button className="stop-button" onClick={handleDownload} disabled={!report}>
              Download {report ? `.${report.filename.split(".").pop()}` : ""}
            </button>
          </div>
        </div>
      </section>
      <section className="surface report-preview">
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

function base64ToArrayBuffer(value: string): ArrayBuffer {
  const binary = window.atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

function formatTimeRange(firstSeen: string, lastSeen: string): string {
  return `${formatTime(firstSeen)} - ${formatTime(lastSeen)}`;
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function EvidencePanel({
  finding,
  evidence,
}: {
  finding: Finding | null;
  evidence: EvidenceLine[];
}) {
  return (
    <section className="surface evidence-surface">
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

function EvidenceReview({
  findings,
  selectedFinding,
  evidence,
  onSelectFinding,
  onOpenRule,
}: {
  findings: Finding[];
  selectedFinding: Finding | null;
  evidence: EvidenceLine[];
  onSelectFinding: (id: string) => void;
  onOpenRule: (ruleId: string) => void;
}) {
  return (
    <section className="evidence-workbench">
      <FindingsPanel
        findings={findings}
        selectedFinding={selectedFinding}
        onSelect={onSelectFinding}
        onOpenRule={onOpenRule}
        emptyText="No findings available. Upload a log or start live monitoring to inspect evidence."
      />
      <section className="surface evidence-main">
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
    <section className="surface evidence-metadata">
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

function SeverityBadge({ severity }: { severity: Finding["severity"] }) {
  return <span className={`severity severity-${severity}`}>{severity}</span>;
}
