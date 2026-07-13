import { useEffect, useState } from "react";
import { AlertTriangle, BookOpen, ClipboardList, Clock3, ListFilter } from "lucide-react";

import { AnalystNote, Finding, Incident, createIncidentNote, listIncidentNotes } from "../../lib/api";
import { formatScoreComponent, formatTime, formatTimeRange } from "./workspaceSelectors";
import { SeverityBadge } from "./WorkspacePrimitives";

export function IncidentOverview({
  incidents,
  selectedIncident,
  onSelectIncident,
}: {
  incidents: Incident[];
  selectedIncident: Incident | null;
  onSelectIncident: (incident: Incident) => void;
}) {
  return (
    <section className="surface incident-surface" data-tour="incident-list">
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

export function IncidentDetail({
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
      <section className="surface incident-detail" data-tour="incident-detail">
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
    <section className="surface incident-detail" data-tour="incident-detail">
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
      <div className="linked-findings" data-tour="incident-linked-findings">
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

function TimelinePanel({ timeline }: { timeline: string[] }) {
  return (
    <div className="timeline-panel" data-tour="incident-timeline">
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

export function FindingsPanel({
  findings,
  selectedFinding,
  onSelect,
  onOpenRule,
  dataTour = "finding-list",
  emptyText = "No findings available.",
}: {
  findings: Finding[];
  selectedFinding: Finding | null;
  onSelect: (id: string) => void;
  onOpenRule: (ruleId: string) => void;
  dataTour?: string;
  emptyText?: string;
}) {
  return (
    <section className="surface" data-tour={dataTour}>
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
