from html import escape

from tracehawk_api.models.domain import Incident

from .common import _report_created_at, _report_filename, _score_component_label
from .models import ReportRequest, ReportResponse
from .redaction import _redact_text, _redact_values


def render_incident_html_report(request: ReportRequest) -> ReportResponse:
    created_at = _report_created_at()
    incident = request.incident
    linked_findings = [
        finding for finding in request.findings if finding.id in set(incident.finding_ids)
    ]
    evidence_blocks = (
        "\n".join(
            f"""
        <section class="evidence-block">
          <h3>Line {line.line_number}</h3>
          <pre>{escape(_redact_text(request, line.raw_text))}</pre>
          <p><strong>SHA-256:</strong> <code>{escape(line.content_hash)}</code></p>
        </section>
        """
            for line in request.evidence
        )
        or "<p>No evidence lines supplied.</p>"
    )
    finding_blocks = (
        "\n".join(
            f"""
        <section class="finding">
          <h3>{escape(_redact_text(request, finding.title))}</h3>
          <dl>
            <dt>Rule</dt><dd><code>{escape(finding.rule_id)}</code></dd>
            <dt>Severity</dt><dd>{escape(finding.severity)}</dd>
            <dt>Confidence</dt><dd>{escape(finding.confidence)}</dd>
            <dt>Events</dt><dd>{finding.event_count}</dd>
            <dt>MITRE</dt><dd>{escape(finding.mitre.technique_id or "unmapped")} {escape(finding.mitre.technique_name or "")}</dd>
          </dl>
          <p>{escape(_redact_text(request, finding.summary))}</p>
          <p>{escape(_redact_text(request, finding.reason))}</p>
        </section>
        """
            for finding in linked_findings
        )
        or "<p>No linked findings supplied.</p>"
    )
    assistant_block = (
        f"""
        <section>
          <h2>Local Assistant Summary</h2>
          <p>{escape(_redact_text(request, request.assistant_summary))}</p>
        </section>
        """
        if request.assistant_summary
        else ""
    )
    scoring_block = _score_html_block(incident, request)
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>TraceHawk Incident Report - {escape(_redact_text(request, incident.title))}</title>
  <style>
    body {{
      margin: 0;
      background: #f4f6f8;
      color: #17202a;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px;
    }}
    header, section {{
      border: 1px solid #d9e0e8;
      background: #ffffff;
      border-radius: 8px;
      margin-bottom: 16px;
      padding: 20px;
    }}
    h1, h2, h3 {{ margin: 0 0 10px; }}
    .meta, dl {{
      display: grid;
      grid-template-columns: 150px minmax(0, 1fr);
      gap: 8px 14px;
    }}
    dt, .label {{
      color: #637083;
      font-weight: 700;
    }}
    dd {{ margin: 0; }}
    .chips {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }}
    .chip {{
      border: 1px solid #d9e0e8;
      background: #f8fafc;
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 12px;
      font-weight: 650;
    }}
    pre {{
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      background: #101820;
      color: #e8eef7;
      border-radius: 6px;
      padding: 12px;
      font-family: "JetBrains Mono", "SFMono-Regular", Consolas, monospace;
      font-size: 12px;
    }}
    code {{
      font-family: "JetBrains Mono", "SFMono-Regular", Consolas, monospace;
    }}
    .integrity li {{ margin-bottom: 6px; }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>TraceHawk Incident Report: {escape(_redact_text(request, incident.title))}</h1>
      <div class="meta">
        <span class="label">Generated</span><span>{created_at.isoformat()}</span>
        <span class="label">Mode</span><span>Local-only deterministic report</span>
        <span class="label">Incident ID</span><span><code>{escape(incident.id)}</code></span>
        <span class="label">Status</span><span>{escape(incident.status)}</span>
        <span class="label">Severity</span><span>{escape(incident.severity)}</span>
        <span class="label">Score</span><span>{incident.score}</span>
        <span class="label">First Seen</span><span>{incident.first_seen.isoformat()}</span>
        <span class="label">Last Seen</span><span>{incident.last_seen.isoformat()}</span>
      </div>
    </header>
    <section>
      <h2>Executive Summary</h2>
      <p>{escape(_redact_text(request, incident.summary))}</p>
      <div class="chips">{_html_chips(_redact_values(request, incident.entities) + incident.mitre_techniques)}</div>
    </section>
    {scoring_block}
    {assistant_block}
    <section>
      <h2>Findings</h2>
      {finding_blocks}
    </section>
    <section>
      <h2>Timeline</h2>
      <ul>{"".join(f"<li><code>{escape(_redact_text(request, item))}</code></li>" for item in incident.timeline) or "<li>No timeline entries supplied.</li>"}</ul>
    </section>
    <section>
      <h2>Evidence</h2>
      {evidence_blocks}
    </section>
    <section class="integrity">
      <h2>Report Integrity Notes</h2>
      <ul>
        <li>Findings are deterministic rule outputs.</li>
        <li>Evidence lines are copied from local logs and include content hashes.</li>
        <li>Assistant text, when present, is explanatory and does not alter findings.</li>
        <li>No cloud service is required to generate this report.</li>
        {("<li>Sensitive values were redacted from rendered report text.</li>" if request.redaction.enabled else "")}
      </ul>
    </section>
  </main>
</body>
</html>
"""

    return ReportResponse(
        format="html",
        filename=_report_filename(incident, extension="html"),
        content=html,
        created_at=created_at,
    )


def _score_html_block(incident: Incident, request: ReportRequest) -> str:
    if not incident.score_breakdown and not incident.score_rationale:
        return ""
    rows = "".join(
        f"<dt>{escape(_score_component_label(component))}</dt><dd>{points}</dd>"
        for component, points in incident.score_breakdown.items()
    )
    rationale = "".join(
        f"<li>{escape(_redact_text(request, item))}</li>" for item in incident.score_rationale
    )
    breakdown_html = f"<dl>{rows}</dl>" if rows else "<p>No score breakdown supplied.</p>"
    rationale_html = f"<ul>{rationale}</ul>" if rationale else "<p>No score rationale supplied.</p>"
    return f"""
    <section>
      <h2>Scoring Rationale</h2>
      {breakdown_html}
      {rationale_html}
    </section>
    """


def _html_chips(values: list[str]) -> str:
    if not values:
        return '<span class="chip">None</span>'
    return "".join(f'<span class="chip">{escape(value)}</span>' for value in values)
