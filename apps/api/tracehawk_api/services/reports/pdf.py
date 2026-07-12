from base64 import b64encode
from io import BytesIO
import textwrap

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

from tracehawk_api.models.domain import Incident
from tracehawk_api.services.analysis import EvidenceLine

from .common import (
    _case_report_filename,
    _report_created_at,
    _report_filename,
    _score_component_label,
    _xml_text,
)
from .models import CaseReportRequest, ReportRequest, ReportResponse
from .redaction import _case_redactor, _redact_text, _redact_values


def render_case_pdf_report(request: CaseReportRequest) -> ReportResponse:
    created_at = _report_created_at()
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
        invariant=1,
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
                        (
                            "Strongest incident",
                            analysis.case_quality.strongest_incident_title or "None",
                        ),
                        ("Strongest score", str(analysis.case_quality.strongest_incident_score)),
                        (
                            "Sequence-backed incidents",
                            str(analysis.case_quality.sequence_backed_incident_count),
                        ),
                        (
                            "Cross-source backed incidents",
                            str(analysis.case_quality.cross_source_corroborated_incident_count),
                        ),
                        (
                            "Total cross-source links",
                            str(analysis.case_quality.total_cross_source_links),
                        ),
                        (
                            "Top scoring reason",
                            _redact_text(redactor, analysis.case_quality.top_scoring_reason),
                        ),
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
                Paragraph(
                    _xml_text(f"{finding.rule_id} | {finding.severity} | {finding.confidence}"),
                    styles["Small"],
                ),
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


def render_incident_pdf_report(request: ReportRequest) -> ReportResponse:
    created_at = _report_created_at()
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
        invariant=1,
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
                Paragraph(
                    _xml_text(_redact_text(request, request.assistant_summary)), styles["Body"]
                ),
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
    story.append(
        _pdf_bullets([f"`{_redact_text(request, item)}`" for item in incident.timeline], styles)
    )

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


def _pdf_evidence_text(value: str) -> str:
    printable = (
        value.replace("\t", "    ").encode("ascii", errors="backslashreplace").decode("ascii")
    )
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
