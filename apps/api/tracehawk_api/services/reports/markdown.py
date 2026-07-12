from tracehawk_api.models.domain import Incident
from tracehawk_api.services.analysis import EvidenceLine

from .common import (
    _case_report_filename,
    _report_created_at,
    _report_filename,
    _score_component_label,
)
from .models import CaseReportRequest, ReportRequest, ReportResponse
from .redaction import _case_redactor, _redact_text, _redact_values


def render_incident_markdown_report(request: ReportRequest) -> ReportResponse:
    created_at = _report_created_at()
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
    created_at = _report_created_at()
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
        lines.extend(
            [
                "## Local Assistant Summary",
                "",
                _redact_text(redactor, request.assistant_summary),
                "",
            ]
        )

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
