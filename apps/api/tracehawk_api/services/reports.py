from base64 import b64encode
from datetime import UTC, datetime
from html import escape
from io import BytesIO
import re
import textwrap

from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from tracehawk_api.models.domain import Finding, Incident
from tracehawk_api.services.analysis import AnalysisResult, EvidenceLine


class ReportRedactionOptions(BaseModel):
    enabled: bool = False
    mask_ips: bool = True
    mask_users: bool = True
    mask_hosts: bool = True


class ReportRequest(BaseModel):
    incident: Incident
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[EvidenceLine] = Field(default_factory=list)
    assistant_summary: str | None = None
    redaction: ReportRedactionOptions = Field(default_factory=ReportRedactionOptions)


class ReportResponse(BaseModel):
    format: str = "markdown"
    filename: str
    content: str
    created_at: datetime


class CaseReportRequest(BaseModel):
    analysis: AnalysisResult
    assistant_summary: str | None = None
    redaction: ReportRedactionOptions = Field(default_factory=ReportRedactionOptions)


def render_incident_markdown_report(request: ReportRequest) -> ReportResponse:
    created_at = datetime.now(UTC)
    incident = request.incident
    linked_findings = [
        finding for finding in request.findings if finding.id in set(incident.finding_ids)
    ]

    lines: list[str] = [
        f"# TraceHawk Incident Report: {_redact_text(request, incident.title)}",
        "",
        f"- **Generated:** {created_at.isoformat()}",
        "- **Mode:** Local-only deterministic report",
        f"- **Incident ID:** `{incident.id}`",
        f"- **Status:** {incident.status}",
        f"- **Severity:** {incident.severity}",
        f"- **Score:** {incident.score}",
        f"- **First Seen:** {incident.first_seen.isoformat()}",
        f"- **Last Seen:** {incident.last_seen.isoformat()}",
        "",
        "## Executive Summary",
        "",
        _redact_text(request, incident.summary),
        "",
        *_score_markdown_lines(incident, request),
    ]

    if request.assistant_summary:
        lines.extend(
            [
                "## Local Assistant Summary",
                "",
                _redact_text(request, request.assistant_summary),
                "",
            ]
        )

    lines.extend(
        [
            "## Entities",
            "",
            _bullet_list(_redact_values(request, incident.entities)),
            "",
            "## MITRE ATT&CK",
            "",
            _bullet_list(incident.mitre_techniques),
            "",
            "## Findings",
            "",
        ]
    )

    if linked_findings:
        for finding in linked_findings:
            technique = finding.mitre.technique_id or "unmapped"
            lines.extend(
                [
                    f"### {_redact_text(request, finding.title)}",
                    "",
                    f"- **Rule:** `{finding.rule_id}`",
                    f"- **Severity:** {finding.severity}",
                    f"- **Confidence:** {finding.confidence}",
                    f"- **Events:** {finding.event_count}",
                    f"- **MITRE:** {technique} {finding.mitre.technique_name or ''}".strip(),
                    "",
                    _redact_text(request, finding.summary),
                    "",
                    _redact_text(request, finding.reason),
                    "",
                ]
            )
    else:
        lines.extend(["No linked findings supplied.", ""])

    lines.extend(["## Timeline", ""])
    if incident.timeline:
        for item in incident.timeline:
            lines.append(f"- `{_redact_text(request, item)}`")
    else:
        lines.append("No timeline entries supplied.")
    lines.append("")

    lines.extend(["## Evidence", ""])
    if request.evidence:
        for line in request.evidence:
            lines.extend(
                [
                    f"### Line {line.line_number}",
                    "",
                    "```text",
                    _redact_text(request, line.raw_text),
                    "```",
                    "",
                    f"- **SHA-256:** `{line.content_hash}`",
                    "",
                ]
            )
    else:
        lines.extend(["No evidence lines supplied.", ""])

    lines.extend(
        [
            "## Report Integrity Notes",
            "",
            "- Findings are deterministic rule outputs.",
            "- Evidence lines are copied from local logs and include content hashes.",
            "- Assistant text, when present, is explanatory and does not alter findings.",
            "- No cloud service is required to generate this report.",
            *(
                ["- Sensitive values were redacted from rendered report text."]
                if request.redaction.enabled
                else []
            ),
            "",
        ]
    )

    return ReportResponse(
        filename=_report_filename(incident),
        content="\n".join(lines).strip() + "\n",
        created_at=created_at,
    )


def render_case_markdown_report(request: CaseReportRequest) -> ReportResponse:
    created_at = datetime.now(UTC)
    analysis = request.analysis
    redactor = _case_redactor(request)
    lines: list[str] = [
        "# TraceHawk Case Report",
        "",
        f"- **Generated:** {created_at.isoformat()}",
        "- **Mode:** Local-only deterministic case report",
        f"- **Analysis ID:** `{analysis.analysis_id or 'not-persisted'}`",
        f"- **Source ID:** `{analysis.source_id}`",
        f"- **Parser:** `{analysis.parser}`",
        f"- **Raw Lines:** {analysis.raw_line_count}",
        f"- **Parsed Events:** {analysis.parsed_event_count}",
        f"- **Findings:** {analysis.finding_count}",
        f"- **Incidents:** {analysis.incident_count}",
        "",
        "## Executive Summary",
        "",
        (
            f"Case bundle correlated {analysis.finding_count} deterministic finding(s) across "
            f"{len(analysis.sources)} source file(s), producing {analysis.incident_count} incident(s) "
            f"and {len(analysis.cross_source_links)} cross-source link(s)."
        ),
        "",
    ]

    if analysis.case_quality:
        lines.extend(
            [
                "## Case Quality Summary",
                "",
                f"- **Strongest incident:** {analysis.case_quality.strongest_incident_title or 'None'}",
                f"- **Strongest score:** {analysis.case_quality.strongest_incident_score}",
                f"- **Sequence-backed incidents:** {analysis.case_quality.sequence_backed_incident_count}",
                (
                    "- **Cross-source corroborated incidents:** "
                    f"{analysis.case_quality.cross_source_corroborated_incident_count}"
                ),
                f"- **Total cross-source links:** {analysis.case_quality.total_cross_source_links}",
                f"- **Top scoring reason:** {_redact_text(redactor, analysis.case_quality.top_scoring_reason)}",
                "",
            ]
        )

    if request.assistant_summary:
        lines.extend(["## Local Assistant Summary", "", _redact_text(redactor, request.assistant_summary), ""])

    lines.extend(["## Sources", ""])
    if analysis.sources:
        lines.extend(
            [
                "| File | Parser | Lines | Events | Findings | SHA-256 |",
                "| --- | --- | ---: | ---: | ---: | --- |",
                *[
                    (
                        f"| `{_redact_text(redactor, source.filename)}` | `{source.parser}` | {source.raw_line_count} | "
                        f"{source.parsed_event_count} | {source.finding_count} | "
                        f"`{source.content_sha256}` |"
                    )
                    for source in analysis.sources
                ],
                "",
            ]
        )
    else:
        lines.extend(["- No source summary supplied.", ""])

    lines.extend(
        [
            "## Correlation Method",
            "",
            "- `http_path_match`: Suricata and Zeek observed the same HTTP path in the same five-minute window.",
            "- `dns_query_match`: Suricata and Zeek observed the same DNS query in the same five-minute window.",
            "- `flow_match`: Suricata and Zeek shared source IP, destination IP, destination port, and timestamp window.",
            "- Every link includes both event IDs and both raw line IDs for line-level review.",
            "",
            "## Cross-Source Links",
            "",
        ]
    )
    if analysis.cross_source_links:
        lines.extend(
            [
                "| Type | Source | Target | Raw Lines | Match | Confidence | Summary |",
                "| --- | --- | --- | --- | --- | --- | --- |",
                *[
                    (
                        f"| `{link.link_type}` | `{_redact_text(redactor, link.source_label)}` | "
                        f"`{_redact_text(redactor, link.target_label)}` | "
                        f"`{link.source_raw_line_id}` -> `{link.target_raw_line_id}` | "
                        f"`{_redact_text(redactor, link.match_value or '')}` | "
                        f"{link.confidence} | {_redact_text(redactor, link.summary)} |"
                    )
                    for link in analysis.cross_source_links[:40]
                ],
                "",
            ]
        )
    else:
        lines.extend(["- No cross-source links supplied.", ""])

    lines.extend(["## Incidents", ""])
    if analysis.incidents:
        for incident in analysis.incidents:
            lines.extend(
                [
                    f"### {incident.title}",
                    "",
                    f"- **Incident ID:** `{incident.id}`",
                    f"- **Severity:** {incident.severity}",
                    f"- **Score:** {incident.score}",
                    f"- **Findings:** {len(incident.finding_ids)}",
                    f"- **First Seen:** {incident.first_seen.isoformat()}",
                    f"- **Last Seen:** {incident.last_seen.isoformat()}",
                    "",
                    _redact_text(redactor, incident.summary),
                    "",
                    *_score_markdown_lines(incident, redactor),
                    "Timeline:",
                    *[f"- `{_redact_text(redactor, item)}`" for item in incident.timeline[:12]],
                    "",
                ]
            )
    else:
        lines.extend(["No incidents supplied.", ""])

    lines.extend(["## Findings", ""])
    for finding in analysis.findings:
        technique = f"{finding.mitre.technique_id or 'unmapped'} {finding.mitre.technique_name or ''}".strip()
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- **Rule:** `{finding.rule_id}`",
                f"- **Severity:** {finding.severity}",
                f"- **Confidence:** {finding.confidence}",
                f"- **Events:** {finding.event_count}",
                f"- **MITRE:** {technique}",
                "",
                _redact_text(redactor, finding.summary),
                "",
            ]
        )

    lines.extend(["## Evidence By Source", ""])
    evidence_by_source: dict[str, list[EvidenceLine]] = {}
    for line in analysis.evidence:
        source_id = line.id.split(":line:", 1)[0]
        evidence_by_source.setdefault(source_id, []).append(line)

    for source in analysis.sources:
        source_lines = evidence_by_source.get(source.source_id, [])
        lines.extend(
            [
                f"### `{_redact_text(redactor, source.filename)}`",
                "",
                f"- **Source SHA-256:** `{source.content_sha256}`",
                f"- **Evidence lines:** {len(source_lines)}",
                "",
            ]
        )
        for line in source_lines[:40]:
            lines.extend(
                [
                    f"#### Line {line.line_number}",
                    "",
                    "```text",
                    _redact_text(redactor, line.raw_text),
                    "```",
                    "",
                    f"- **SHA-256:** `{line.content_hash}`",
                    "",
                ]
            )

    lines.extend(
        [
            "## Report Integrity Notes",
            "",
            "- Sources are preserved with content hashes.",
            "- Findings are deterministic rule outputs.",
            "- Cross-source links are derived from matching IPs, ports, DNS queries, HTTP paths, and timestamps.",
            "- Cross-source links preserve source and target raw line IDs.",
            "- No cloud service is required to generate this report.",
            *(
                ["- Sensitive values were redacted from rendered report text."]
                if request.redaction.enabled
                else []
            ),
            "",
        ]
    )
    return ReportResponse(
        filename=_case_report_filename(analysis),
        content="\n".join(lines).strip() + "\n",
        created_at=created_at,
    )


def render_case_pdf_report(request: CaseReportRequest) -> ReportResponse:
    created_at = datetime.now(UTC)
    analysis = request.analysis
    redactor = _case_redactor(request)
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.65 * inch,
        title="TraceHawk Case Report",
    )
    styles = _pdf_styles()
    story = [
        Paragraph("TraceHawk Case Report", styles["Title"]),
        Spacer(1, 10),
        _pdf_meta_table(
            [
                ("Generated", created_at.isoformat()),
                ("Mode", "Local-only deterministic case report"),
                ("Analysis ID", analysis.analysis_id or "not-persisted"),
                ("Parser", analysis.parser),
                ("Raw Lines", str(analysis.raw_line_count)),
                ("Parsed Events", str(analysis.parsed_event_count)),
                ("Findings", str(analysis.finding_count)),
                ("Incidents", str(analysis.incident_count)),
                ("Cross Links", str(len(analysis.cross_source_links))),
            ],
            styles,
        ),
        Spacer(1, 12),
        Paragraph("Executive Summary", styles["Heading2"]),
        Paragraph(
            _xml_text(
                f"Case bundle correlated {analysis.finding_count} finding(s) across "
                f"{len(analysis.sources)} source file(s)."
            ),
            styles["Body"],
        ),
    ]

    if analysis.case_quality:
        story.extend(
            [
                Spacer(1, 8),
                Paragraph("Case Quality Summary", styles["Heading2"]),
                _pdf_meta_table(
                    [
                        ("Strongest incident", analysis.case_quality.strongest_incident_title or "None"),
                        ("Strongest score", str(analysis.case_quality.strongest_incident_score)),
                        ("Sequence-backed incidents", str(analysis.case_quality.sequence_backed_incident_count)),
                        (
                            "Cross-source backed incidents",
                            str(analysis.case_quality.cross_source_corroborated_incident_count),
                        ),
                        ("Total cross-source links", str(analysis.case_quality.total_cross_source_links)),
                        ("Top scoring reason", _redact_text(redactor, analysis.case_quality.top_scoring_reason)),
                    ],
                    styles,
                ),
            ]
        )

    story.extend([Spacer(1, 10), Paragraph("Sources", styles["Heading2"])])
    for source in analysis.sources:
        story.append(
            Paragraph(
                _xml_text(
                    f"{_redact_text(redactor, source.filename)} | {source.parser} | lines={source.raw_line_count} | "
                    f"events={source.parsed_event_count} | sha256={source.content_sha256}"
                ),
                styles["Small"],
            )
        )

    story.extend([PageBreak(), Paragraph("Cross-Source Links", styles["Heading2"])])
    story.append(Paragraph("Correlation Method", styles["Heading3"]))
    story.append(
        _pdf_bullets(
            [
                "http_path_match links matching HTTP paths within five minutes.",
                "dns_query_match links matching DNS queries within five minutes.",
                "flow_match links shared source IP, destination IP, destination port, and timestamp window.",
                "Each link preserves both event IDs and raw line IDs.",
            ],
            styles,
        )
    )
    story.append(
        _pdf_bullets(
            [
                _redact_text(
                    redactor,
                    f"{link.link_type}: {link.source_label} -> {link.target_label}; "
                    f"raw={link.source_raw_line_id}->{link.target_raw_line_id}; "
                    f"match={link.match_value}; {link.summary}",
                )
                for link in analysis.cross_source_links[:40]
            ],
            styles,
        )
    )

    story.extend([PageBreak(), Paragraph("Incidents", styles["Heading2"])])
    for incident in analysis.incidents:
        story.extend(
            [
                Paragraph(_xml_text(incident.title), styles["Heading3"]),
                _pdf_meta_table(
                    [
                        ("Incident ID", incident.id),
                        ("Severity", incident.severity),
                        ("Score", str(incident.score)),
                        ("Findings", str(len(incident.finding_ids))),
                    ],
                    styles,
                ),
                Paragraph(_xml_text(_redact_text(redactor, incident.summary)), styles["Body"]),
                *_pdf_score_story(incident, redactor, styles),
                Spacer(1, 8),
            ]
        )

    story.extend([PageBreak(), Paragraph("Findings", styles["Heading2"])])
    for finding in analysis.findings:
        story.extend(
            [
                Paragraph(_xml_text(finding.title), styles["Heading3"]),
                Paragraph(_xml_text(f"{finding.rule_id} | {finding.severity} | {finding.confidence}"), styles["Small"]),
                Paragraph(_xml_text(_redact_text(redactor, finding.summary)), styles["Body"]),
            ]
        )

    story.extend([PageBreak(), Paragraph("Evidence By Source", styles["Heading2"])])
    evidence_by_source: dict[str, list[EvidenceLine]] = {}
    for line in analysis.evidence:
        source_id = line.id.split(":line:", 1)[0]
        evidence_by_source.setdefault(source_id, []).append(line)
    for source in analysis.sources:
        story.extend(
            [
                Paragraph(_xml_text(_redact_text(redactor, source.filename)), styles["Heading3"]),
                Paragraph(f"Source SHA-256: {_xml_text(source.content_sha256)}", styles["Small"]),
            ]
        )
        for line in evidence_by_source.get(source.source_id, [])[:25]:
            story.append(
                KeepTogether(
                    [
                        Paragraph(f"Line {line.line_number}", styles["Heading3"]),
                        Preformatted(
                            _pdf_evidence_text(_redact_text(redactor, line.raw_text)),
                            styles["Mono"],
                        ),
                        Paragraph(f"SHA-256: {_xml_text(line.content_hash)}", styles["Small"]),
                        Spacer(1, 8),
                    ]
                )
            )

    document.build(story, onFirstPage=_pdf_footer, onLaterPages=_pdf_footer)
    return ReportResponse(
        format="pdf",
        filename=_case_report_filename(analysis, extension="pdf"),
        content=b64encode(buffer.getvalue()).decode("ascii"),
        created_at=created_at,
    )


def render_incident_html_report(request: ReportRequest) -> ReportResponse:
    created_at = datetime.now(UTC)
    incident = request.incident
    linked_findings = [
        finding for finding in request.findings if finding.id in set(incident.finding_ids)
    ]
    evidence_blocks = "\n".join(
        f"""
        <section class="evidence-block">
          <h3>Line {line.line_number}</h3>
          <pre>{escape(_redact_text(request, line.raw_text))}</pre>
          <p><strong>SHA-256:</strong> <code>{escape(line.content_hash)}</code></p>
        </section>
        """
        for line in request.evidence
    ) or "<p>No evidence lines supplied.</p>"
    finding_blocks = "\n".join(
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
    ) or "<p>No linked findings supplied.</p>"
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
      <ul>{''.join(f'<li><code>{escape(_redact_text(request, item))}</code></li>' for item in incident.timeline) or '<li>No timeline entries supplied.</li>'}</ul>
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
        {('<li>Sensitive values were redacted from rendered report text.</li>' if request.redaction.enabled else '')}
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


def render_incident_pdf_report(request: ReportRequest) -> ReportResponse:
    created_at = datetime.now(UTC)
    incident = request.incident
    linked_findings = [
        finding for finding in request.findings if finding.id in set(incident.finding_ids)
    ]
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.65 * inch,
        title=f"TraceHawk Incident Report - {_redact_text(request, incident.title)}",
    )
    styles = _pdf_styles()
    story = [
        Paragraph(
            f"TraceHawk Incident Report: {_xml_text(_redact_text(request, incident.title))}",
            styles["Title"],
        ),
        Spacer(1, 10),
        _pdf_meta_table(
            [
                ("Generated", created_at.isoformat()),
                ("Mode", "Local-only deterministic report"),
                ("Incident ID", incident.id),
                ("Status", incident.status),
                ("Severity", incident.severity),
                ("Score", str(incident.score)),
                ("First Seen", incident.first_seen.isoformat()),
                ("Last Seen", incident.last_seen.isoformat()),
            ],
            styles,
        ),
        Spacer(1, 14),
        Paragraph("Executive Summary", styles["Heading2"]),
        Paragraph(_xml_text(_redact_text(request, incident.summary)), styles["Body"]),
        *_pdf_score_story(incident, request, styles),
        Spacer(1, 10),
        Paragraph("Entities", styles["Heading2"]),
        _pdf_bullets(_redact_values(request, incident.entities), styles),
        Spacer(1, 8),
        Paragraph("MITRE ATT&amp;CK", styles["Heading2"]),
        _pdf_bullets(incident.mitre_techniques, styles),
    ]

    if request.assistant_summary:
        story.extend(
            [
                Spacer(1, 10),
                Paragraph("Local Assistant Summary", styles["Heading2"]),
                Paragraph(_xml_text(_redact_text(request, request.assistant_summary)), styles["Body"]),
            ]
        )

    story.extend([PageBreak(), Paragraph("Findings", styles["Heading2"])])
    if linked_findings:
        for finding in linked_findings:
            technique = f"{finding.mitre.technique_id or 'unmapped'} {finding.mitre.technique_name or ''}".strip()
            story.extend(
                [
                    Paragraph(_xml_text(_redact_text(request, finding.title)), styles["Heading3"]),
                    _pdf_meta_table(
                        [
                            ("Rule", finding.rule_id),
                            ("Severity", finding.severity),
                            ("Confidence", finding.confidence),
                            ("Events", str(finding.event_count)),
                            ("MITRE", technique),
                        ],
                        styles,
                    ),
                    Spacer(1, 6),
                    Paragraph(_xml_text(_redact_text(request, finding.summary)), styles["Body"]),
                    Paragraph(_xml_text(_redact_text(request, finding.reason)), styles["Body"]),
                    Spacer(1, 10),
                ]
            )
    else:
        story.append(Paragraph("No linked findings supplied.", styles["Body"]))

    story.extend([PageBreak(), Paragraph("Timeline", styles["Heading2"])])
    story.append(_pdf_bullets([f"`{_redact_text(request, item)}`" for item in incident.timeline], styles))

    story.extend([PageBreak(), Paragraph("Evidence", styles["Heading2"])])
    if request.evidence:
        for line in request.evidence:
            story.append(
                KeepTogether(
                    [
                        Paragraph(f"Line {line.line_number}", styles["Heading3"]),
                        Preformatted(
                            _pdf_evidence_text(_redact_text(request, line.raw_text)),
                            styles["Mono"],
                        ),
                        Paragraph(f"SHA-256: {_xml_text(line.content_hash)}", styles["Small"]),
                        Spacer(1, 8),
                    ]
                )
            )
    else:
        story.append(Paragraph("No evidence lines supplied.", styles["Body"]))

    story.extend(
        [
            PageBreak(),
            Paragraph("Report Integrity Notes", styles["Heading2"]),
            _pdf_bullets(
                [
                    "Findings are deterministic rule outputs.",
                    "Evidence lines are copied from local logs and include content hashes.",
                    "Assistant text, when present, is explanatory and does not alter findings.",
                    "No cloud service is required to generate this report.",
                    *(
                        ["Sensitive values were redacted from rendered report text."]
                        if request.redaction.enabled
                        else []
                    ),
                ],
                styles,
            ),
        ]
    )

    document.build(story, onFirstPage=_pdf_footer, onLaterPages=_pdf_footer)
    return ReportResponse(
        format="pdf",
        filename=_report_filename(incident, extension="pdf"),
        content=b64encode(buffer.getvalue()).decode("ascii"),
        created_at=created_at,
    )


def _bullet_list(values: list[str]) -> str:
    if not values:
        return "- None"
    return "\n".join(f"- {value}" for value in values)


def _score_markdown_lines(incident: Incident, request: ReportRequest) -> list[str]:
    if not incident.score_breakdown and not incident.score_rationale:
        return []
    lines = ["## Scoring Rationale", ""]
    if incident.score_breakdown:
        lines.extend(["| Component | Points |", "| --- | ---: |"])
        lines.extend(
            f"| {_score_component_label(component)} | {points} |"
            for component, points in incident.score_breakdown.items()
        )
        lines.append("")
    if incident.score_rationale:
        lines.extend(
            [
                "Rationale:",
                *[f"- {_redact_text(request, item)}" for item in incident.score_rationale],
                "",
            ]
        )
    return lines


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


def _pdf_score_story(
    incident: Incident,
    request: ReportRequest,
    styles: dict[str, ParagraphStyle],
) -> list[object]:
    if not incident.score_breakdown and not incident.score_rationale:
        return []
    flowables: list[object] = [Spacer(1, 8), Paragraph("Scoring Rationale", styles["Heading2"])]
    if incident.score_breakdown:
        flowables.append(
            _pdf_meta_table(
                [
                    (_score_component_label(component), str(points))
                    for component, points in incident.score_breakdown.items()
                ],
                styles,
            )
        )
    if incident.score_rationale:
        flowables.append(
            _pdf_bullets([_redact_text(request, item) for item in incident.score_rationale], styles)
        )
    return flowables


def _score_component_label(component: str) -> str:
    return " ".join(part.capitalize() for part in component.split("_"))


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ENTITY_USER_RE = re.compile(r"\buser:[^\s,;]+", flags=re.IGNORECASE)
ENTITY_HOST_RE = re.compile(r"\bhost:[^\s,;]+", flags=re.IGNORECASE)
AUTH_USER_RE = re.compile(r"\b(?:for|user|username=)\s+([A-Za-z0-9_.@-]+)", flags=re.IGNORECASE)
HOST_ASSIGNMENT_RE = re.compile(r"\b(?:host|hostname)=([A-Za-z0-9_.-]+)", flags=re.IGNORECASE)


def _redact_values(request: ReportRequest, values: list[str]) -> list[str]:
    return [_redact_text(request, value) for value in values]


def _redact_text(request: ReportRequest, value: str | None) -> str:
    if value is None:
        return ""
    if not request.redaction.enabled:
        return value

    redacted = value
    if request.redaction.mask_ips:
        redacted = IPV4_RE.sub("[REDACTED_IP]", redacted)
        redacted = re.sub(r"\b(ip|dst|src):[^\s,;]+", r"\1:[REDACTED_IP]", redacted)
    if request.redaction.mask_users:
        redacted = ENTITY_USER_RE.sub("user:[REDACTED_USER]", redacted)
        redacted = AUTH_USER_RE.sub(lambda match: match.group(0).replace(match.group(1), "[REDACTED_USER]"), redacted)
        for username in _entity_values(request, "user:"):
            redacted = re.sub(
                rf"\b{re.escape(username)}\b",
                "[REDACTED_USER]",
                redacted,
                flags=re.IGNORECASE,
            )
    if request.redaction.mask_hosts:
        redacted = ENTITY_HOST_RE.sub("host:[REDACTED_HOST]", redacted)
        redacted = HOST_ASSIGNMENT_RE.sub(lambda match: match.group(0).replace(match.group(1), "[REDACTED_HOST]"), redacted)
        for hostname in _entity_values(request, "host:"):
            redacted = re.sub(
                rf"\b{re.escape(hostname)}\b",
                "[REDACTED_HOST]",
                redacted,
                flags=re.IGNORECASE,
            )
    return redacted


def _entity_values(request: ReportRequest, prefix: str) -> list[str]:
    values: list[str] = []
    for entity in request.incident.entities:
        if entity.lower().startswith(prefix):
            value = entity.split(":", 1)[1].strip()
            if value:
                values.append(value)
    return values


def _case_redactor(request: CaseReportRequest) -> ReportRequest:
    entities = sorted(
        {
            entity
            for incident in request.analysis.incidents
            for entity in incident.entities
        }
    )
    incident = Incident(
        id=request.analysis.analysis_id or request.analysis.source_id,
        title="Case report",
        severity="info",
        summary="Case redaction context",
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        score=0,
        entities=entities,
    )
    return ReportRequest(incident=incident, redaction=request.redaction)


def _html_chips(values: list[str]) -> str:
    if not values:
        return '<span class="chip">None</span>'
    return "".join(f'<span class="chip">{escape(value)}</span>' for value in values)


def _pdf_styles() -> dict[str, ParagraphStyle]:
    sample = getSampleStyleSheet()
    return {
        "Title": ParagraphStyle(
            "TraceHawkTitle",
            parent=sample["Title"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#17202a"),
            spaceAfter=8,
        ),
        "Heading2": ParagraphStyle(
            "TraceHawkHeading2",
            parent=sample["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#17202a"),
            spaceBefore=8,
            spaceAfter=6,
        ),
        "Heading3": ParagraphStyle(
            "TraceHawkHeading3",
            parent=sample["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#17202a"),
            spaceBefore=8,
            spaceAfter=5,
        ),
        "Body": ParagraphStyle(
            "TraceHawkBody",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#243044"),
            spaceAfter=5,
        ),
        "Small": ParagraphStyle(
            "TraceHawkSmall",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#526071"),
        ),
        "Mono": ParagraphStyle(
            "TraceHawkMono",
            parent=sample["Code"],
            fontName="Courier",
            fontSize=7.4,
            leading=9.5,
            backColor=colors.HexColor("#f4f6f8"),
            borderColor=colors.HexColor("#d9e0e8"),
            borderWidth=0.5,
            borderPadding=5,
            textColor=colors.HexColor("#17202a"),
        ),
    }


def _pdf_meta_table(rows: list[tuple[str, str]], styles: dict[str, ParagraphStyle]) -> Table:
    table_rows = [
        [Paragraph(_xml_text(label), styles["Small"]), Paragraph(_xml_text(value), styles["Body"])]
        for label, value in rows
    ]
    table = Table(table_rows, colWidths=[1.25 * inch, 5.6 * inch], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _pdf_bullets(values: list[str], styles: dict[str, ParagraphStyle]) -> ListFlowable:
    items = values or ["None"]
    return ListFlowable(
        [ListItem(Paragraph(_xml_text(item), styles["Body"])) for item in items],
        bulletType="bullet",
        leftIndent=14,
    )


def _pdf_footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#637083"))
    canvas.drawString(0.65 * inch, 0.38 * inch, "TraceHawk local-only incident report")
    canvas.drawRightString(7.85 * inch, 0.38 * inch, f"Page {document.page}")
    canvas.restoreState()


def _xml_text(value: str) -> str:
    return escape(value, quote=False)


def _pdf_evidence_text(value: str) -> str:
    printable = value.replace("\t", "    ").encode("ascii", errors="backslashreplace").decode("ascii")
    wrapped: list[str] = []
    for line in printable.splitlines() or [""]:
        wrapped.extend(
            textwrap.wrap(
                line,
                width=96,
                replace_whitespace=False,
                drop_whitespace=False,
                break_long_words=True,
                break_on_hyphens=False,
            )
            or [""]
        )
    return "\n".join(wrapped)


def _report_filename(incident: Incident, *, extension: str = "md") -> str:
    safe_title = "".join(
        char.lower() if char.isalnum() else "-" for char in incident.title
    ).strip("-")
    safe_title = "-".join(part for part in safe_title.split("-") if part)
    return f"tracehawk-{safe_title or 'incident'}-{incident.id[-8:]}.{extension}"


def _case_report_filename(analysis: AnalysisResult, *, extension: str = "md") -> str:
    safe_source = "".join(
        char.lower() if char.isalnum() else "-" for char in analysis.source_id
    ).strip("-")
    safe_source = "-".join(part for part in safe_source.split("-") if part)
    return f"tracehawk-case-{safe_source or 'bundle'}.{extension}"
