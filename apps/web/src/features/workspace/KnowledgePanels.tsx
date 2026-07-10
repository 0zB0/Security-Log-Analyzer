import { useEffect, useMemo, useState } from "react";
import { Activity, BookOpen, Fingerprint } from "lucide-react";

import { AnalysisResult, Finding, Incident, RuleLibraryItem, getRuleLibrary } from "../../lib/api";
import { buildMitreGroups, shortId } from "./workspaceSelectors";
import { SeverityBadge } from "./WorkspacePrimitives";

export function EntityInventory({
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

export function MitreMapPanel({
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

export function DetectionLibrary({
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
