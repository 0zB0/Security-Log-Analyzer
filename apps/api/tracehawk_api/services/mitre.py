from pydantic import BaseModel, Field

from tracehawk_api.models.domain import Finding, Severity


class MitreTechniqueSummary(BaseModel):
    tactic: str
    technique_id: str | None = None
    technique_name: str | None = None
    finding_count: int = 0
    max_severity: Severity = "info"
    rule_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    evidence_line_ids: list[str] = Field(default_factory=list)


class MitreSummary(BaseModel):
    analysis_id: str
    technique_count: int
    finding_count: int
    unmapped_finding_count: int
    tactics: list[str]
    techniques: list[MitreTechniqueSummary]


SEVERITY_RANK: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def build_mitre_summary(analysis_id: str, findings: list[Finding]) -> MitreSummary:
    groups: dict[tuple[str, str | None], MitreTechniqueSummary] = {}
    for finding in findings:
        tactic = finding.mitre.tactic or "Unmapped"
        technique_id = finding.mitre.technique_id
        key = (tactic, technique_id)
        summary = groups.setdefault(
            key,
            MitreTechniqueSummary(
                tactic=tactic,
                technique_id=technique_id,
                technique_name=finding.mitre.technique_name,
            ),
        )
        summary.finding_count += 1
        if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[summary.max_severity]:
            summary.max_severity = finding.severity
        if finding.rule_id not in summary.rule_ids:
            summary.rule_ids.append(finding.rule_id)
        summary.finding_ids.append(finding.id)
        for line_id in finding.evidence_line_ids:
            if line_id not in summary.evidence_line_ids:
                summary.evidence_line_ids.append(line_id)

    techniques = sorted(
        groups.values(),
        key=lambda item: (item.tactic == "Unmapped", item.tactic, item.technique_id or ""),
    )
    return MitreSummary(
        analysis_id=analysis_id,
        technique_count=len(techniques),
        finding_count=len(findings),
        unmapped_finding_count=sum(1 for finding in findings if finding.mitre.technique_id is None),
        tactics=sorted({summary.tactic for summary in techniques}),
        techniques=techniques,
    )
