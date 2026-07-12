import { useEffect, useRef, useState } from "react";
import { Pause, Play, Save, Square } from "lucide-react";

import { AnalysisResult, LiveSnapshot, liveFileWebSocketUrl, liveInterfaceWebSocketUrl, persistLiveSnapshot } from "../../lib/api";
import { CAPTURE_PRESETS } from "../../app/workspaceOptions";

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
        <span>
          {latestSnapshot?.live_retention.retained_raw_lines ?? 0}/
          {latestSnapshot?.live_retention.total_raw_lines ?? 0} retained lines
        </span>
        <span>{latestSnapshot?.live_retention.dropped_raw_lines ?? 0} dropped lines</span>
        <span>{latestSnapshot?.live_retention.dropped_parsed_events ?? 0} dropped events</span>
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
    evidence_integrity: null,
    live_retention: snapshot.live_retention,
    live_snapshot_attestation: snapshot.live_snapshot_attestation,
  };
}
