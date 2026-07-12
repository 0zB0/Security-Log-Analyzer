from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from tracehawk_api.database import get_session
from tracehawk_api.config import settings
from tracehawk_api.models.domain import Incident, RawLogLine
from tracehawk_api.services.analysis import AnalysisResult, EvidenceLine, analyze_text
from tracehawk_api.services.case_bundle import CaseBundleInput, analyze_case_bundle
from tracehawk_api.services.ingest import build_raw_lines_from_text
from tracehawk_api.services.live_attestation import verify_live_snapshot_attestation
from tracehawk_api.services.persistence import (
    AnalysisRunSummary,
    get_analysis_result,
    list_analysis_runs,
    list_incidents,
    persist_analysis,
)
from tracehawk_api.services.uploads import read_validated_upload


router = APIRouter(prefix="/api/analyze", tags=["analysis"])
SessionDep = Annotated[Session, Depends(get_session)]

SAMPLE_INPUTS = {
    "auth-ssh-compromise": "packages/sample-data/auth/ssh-bruteforce.log",
    "suricata-alert-burst": "packages/sample-data/suricata/eve-alerts.jsonl",
    "suricata-c2-http-dns": "packages/sample-data/suricata/eve-c2-dns.jsonl",
    "zeek-port-scan": "packages/sample-data/zeek/conn-port-scan.log",
    "zeek-dns-http-notice": "packages/sample-data/zeek/zeek-mixed.jsonl",
    "cloudtrail-iam-risk": "packages/sample-data/cloudtrail/iam-risk.jsonl",
    "kubernetes-audit-risk": "packages/sample-data/kubernetes/audit-risk.jsonl",
    "windows-security-risk": "packages/sample-data/windows/security-risk.jsonl",
}


@router.post("/upload", response_model=AnalysisResult)
async def analyze_upload(session: SessionDep, file: UploadFile = File(...)) -> AnalysisResult:
    upload = await read_validated_upload(file)
    try:
        return _analyze_and_persist(session, upload.text, upload.filename)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/case-bundle", response_model=AnalysisResult)
async def analyze_case_bundle_upload(
    session: SessionDep,
    files: Annotated[list[UploadFile], File(...)],
) -> AnalysisResult:
    if len(files) > settings.max_case_files:
        raise HTTPException(
            status_code=413,
            detail=f"Case bundle exceeds the {settings.max_case_files} file limit.",
        )
    inputs: list[CaseBundleInput] = []
    total_bytes = 0
    for file in files:
        upload = await read_validated_upload(file)
        total_bytes += upload.byte_count
        if total_bytes > settings.max_case_total_bytes:
            raise HTTPException(
                status_code=413,
                detail=(
                    "Case bundle exceeds the "
                    f"{settings.max_case_total_bytes} total byte limit."
                ),
            )
        inputs.append(CaseBundleInput(filename=upload.filename, text=upload.text))

    try:
        return _analyze_case_bundle_and_persist(session, inputs, case_name="uploaded-case-bundle")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/demo", response_model=AnalysisResult)
def analyze_demo(session: SessionDep) -> AnalysisResult:
    sample_path = _project_root() / "packages/sample-data/auth/ssh-bruteforce.log"
    if not sample_path.exists():
        raise HTTPException(status_code=404, detail="Demo log sample was not found.")

    try:
        return _analyze_and_persist(session, sample_path.read_text(), sample_path.name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/case-sample/real-lab", response_model=AnalysisResult)
def analyze_real_lab_case_sample(session: SessionDep) -> AnalysisResult:
    root = _project_root()
    sample_paths = [
        root / "docs/proof-pack/v0.4.1-real-lab/engine-output/zeek/conn.log",
        root / "docs/proof-pack/v0.4.1-real-lab/engine-output/zeek/dns.log",
        root / "docs/proof-pack/v0.4.1-real-lab/engine-output/zeek/http.log",
        root / "docs/proof-pack/v0.4.1-real-lab/engine-output/suricata/eve.json",
    ]
    missing = [path for path in sample_paths if not path.exists()]
    if missing:
        raise HTTPException(status_code=404, detail="Real lab proof pack was not found.")

    inputs = [
        CaseBundleInput(filename=path.name, text=path.read_text(encoding="utf-8"))
        for path in sample_paths
    ]
    try:
        return _analyze_case_bundle_and_persist(session, inputs, case_name="real-lab-case")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/sample/{sample_id}", response_model=AnalysisResult)
def analyze_sample(sample_id: str, session: SessionDep) -> AnalysisResult:
    sample_relative_path = SAMPLE_INPUTS.get(sample_id)
    if sample_relative_path is None:
        raise HTTPException(status_code=404, detail="Sample was not found.")

    sample_path = _project_root() / sample_relative_path
    if not sample_path.exists():
        raise HTTPException(status_code=404, detail="Sample file was not found.")

    try:
        return _analyze_and_persist(session, sample_path.read_text(), sample_path.name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/live-snapshot", response_model=AnalysisResult)
def persist_live_snapshot(snapshot: AnalysisResult, session: SessionDep) -> AnalysisResult:
    if snapshot.parser in {"", "detecting"}:
        raise HTTPException(status_code=422, detail="Live snapshot does not have a parser yet.")
    if not snapshot.evidence:
        raise HTTPException(status_code=422, detail="Live snapshot has no evidence to persist.")

    try:
        verify_live_snapshot_attestation(snapshot)
        created_at = datetime.now(UTC)
        analysis_id = _live_analysis_id(snapshot.source_id, created_at)
        result = _namespace_live_result(snapshot, analysis_id)
        raw_lines = _raw_lines_from_evidence(result.source_id, result.evidence, created_at)
        filename = f"live-{snapshot.parser}-{created_at.strftime('%Y%m%d-%H%M%S')}.json"

        return persist_analysis(
            session,
            result,
            raw_lines,
            filename,
            source_type=_live_source_type(snapshot.source_id),
            analysis_id=analysis_id,
            evidence_origin="live_snapshot",
            attested_live_snapshot=True,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/runs", response_model=list[AnalysisRunSummary])
def recent_analysis_runs(session: SessionDep) -> list[AnalysisRunSummary]:
    return list_analysis_runs(session)


@router.get("/runs/{analysis_id}", response_model=AnalysisResult)
def analysis_run_detail(analysis_id: str, session: SessionDep) -> AnalysisResult:
    result = get_analysis_result(session, analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return result


@router.get("/incidents", response_model=list[Incident])
def recent_incidents(session: SessionDep, analysis_id: str | None = None) -> list[Incident]:
    return list_incidents(session, analysis_id=analysis_id)


def _analyze_and_persist(session: Session, text: str, filename: str) -> AnalysisResult:
    result = analyze_text(
        text=text,
        filename=filename,
        rules_root=_project_root() / "packages/rules",
    )
    raw_lines = build_raw_lines_from_text(text, result.source_id)
    return persist_analysis(session, result, raw_lines, filename)


def _analyze_case_bundle_and_persist(
    session: Session,
    inputs: list[CaseBundleInput],
    *,
    case_name: str,
) -> AnalysisResult:
    case = analyze_case_bundle(
        inputs,
        rules_root=_project_root() / "packages/rules",
        case_name=case_name,
    )
    return persist_analysis(
        session,
        case.result,
        case.raw_lines,
        f"{case_name}.bundle",
        source_type="upload",
    )


def _live_analysis_id(source_id: str, created_at: datetime) -> str:
    digest = sha256(f"live:{source_id}:{created_at.isoformat()}".encode("utf-8")).hexdigest()[:16]
    return f"analysis:{digest}"


def _namespace_live_result(snapshot: AnalysisResult, analysis_id: str) -> AnalysisResult:
    namespace = analysis_id.replace(":", "-")
    source_id = f"{snapshot.source_id}:saved:{namespace}"
    raw_id_map = {line.id: f"{namespace}:{line.id}" for line in snapshot.evidence}
    finding_id_map = {finding.id: f"{namespace}:{finding.id}" for finding in snapshot.findings}

    evidence = [line.model_copy(update={"id": raw_id_map[line.id]}) for line in snapshot.evidence]
    events = [
        event.model_copy(
            update={
                "id": f"{namespace}:{event.id}",
                "source_id": source_id,
                "raw_line_id": raw_id_map.get(event.raw_line_id, f"{namespace}:{event.raw_line_id}"),
            }
        )
        for event in snapshot.events
    ]
    findings = [
        finding.model_copy(
            update={
                "id": finding_id_map[finding.id],
                "evidence_line_ids": [
                    raw_id_map.get(line_id, f"{namespace}:{line_id}")
                    for line_id in finding.evidence_line_ids
                ],
            }
        )
        for finding in snapshot.findings
    ]
    incidents = [
        incident.model_copy(
            update={
                "id": f"{namespace}:{incident.id}",
                "finding_ids": [
                    finding_id_map.get(finding_id, f"{namespace}:{finding_id}")
                    for finding_id in incident.finding_ids
                ],
            }
        )
        for incident in snapshot.incidents
    ]

    return AnalysisResult(
        analysis_id=analysis_id,
        source_id=source_id,
        parser=snapshot.parser,
        raw_line_count=len(evidence),
        parsed_event_count=len(events),
        finding_count=len(findings),
        incident_count=len(incidents),
        events=events,
        findings=findings,
        incidents=incidents,
        evidence=evidence,
        live_retention=snapshot.live_retention,
    )


def _raw_lines_from_evidence(
    source_id: str,
    evidence: list[EvidenceLine],
    timestamp_observed: datetime,
) -> list[RawLogLine]:
    return [
        RawLogLine(
            id=line.id,
            source_id=source_id,
            line_number=line.line_number,
            raw_text=line.raw_text,
            content_hash=line.content_hash,
            timestamp_observed=timestamp_observed,
        )
        for line in evidence
    ]


def _live_source_type(source_id: str) -> str:
    if source_id.startswith("interface:"):
        return "interface_packets"
    if source_id.startswith("docker:"):
        return "docker_logs"
    return "file_watch"


def _project_root() -> Path:
    return Path(__file__).resolve().parents[4]
