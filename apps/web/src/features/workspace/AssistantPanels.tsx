import { useEffect, useMemo, useState } from "react";
import { BrainCircuit, ClipboardList } from "lucide-react";

import { AnalysisResult, AssistantResponse, AssistantSettings, AssistantStatus, EvidenceLine, Finding, Incident, explainIncident, getAssistantSettings, previewAssistantPrompt, updateAssistantSettings } from "../../lib/api";

export function SettingsPanel({
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
        {error ? (
          <div className="error-banner compact-error">{error}</div>
        ) : (
          <div className="empty-state">Loading settings.</div>
        )}
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

export function AssistantPanel({
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
