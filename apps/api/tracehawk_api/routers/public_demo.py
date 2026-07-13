from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from tracehawk_api.config import DEPLOYMENT_PROFILE_PUBLIC_DEMO, settings
from tracehawk_api.services.analysis import AnalysisResult, analyze_text
from tracehawk_api.services.entities import build_entities
from tracehawk_api.services.evidence_integrity import verify_analysis_integrity
from tracehawk_api.services.ingest import build_raw_lines_from_text
from tracehawk_api.services.reports import (
    CaseReportRequest,
    ReportRequest,
    ReportResponse,
    render_case_markdown_report,
    render_incident_markdown_report,
)
from tracehawk_api.security import PUBLIC_DEMO_CONCURRENCY


router = APIRouter(prefix="/api/public-demo", tags=["public-demo"])

SAMPLE_INPUTS = {
    "auth-ssh-compromise": "packages/sample-data/auth/ssh-bruteforce.log",
    "suricata-alert-burst": "packages/sample-data/suricata/eve-alerts.jsonl",
    "zeek-port-scan": "packages/sample-data/zeek/conn-port-scan.log",
}
PUBLIC_VIEWS = (
    "upload",
    "incidents",
    "findings",
    "evidence",
    "entities",
    "mitre",
    "reports",
    "library",
    "tutorial",
)


class PublicDemoStatus(BaseModel):
    enabled: bool
    profile: Literal["private", "public_demo"]
    storage: Literal["disabled"] = "disabled"
    external_ai: bool = False
    max_bytes: int
    max_lines: int
    session_timeout_seconds: int
    allowed_extensions: list[str]
    available_views: list[str]


class PublicDemoAnalyzeRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1)


class PublicDemoAnalysisResponse(BaseModel):
    analysis: AnalysisResult
    ephemeral: Literal[True] = True
    stored: Literal[False] = False
    external_ai: Literal[False] = False
    lifecycle: Literal["request_and_browser_memory_only"] = (
        "request_and_browser_memory_only"
    )
    session_timeout_seconds: int


@router.get("/status", response_model=PublicDemoStatus)
def public_demo_status() -> PublicDemoStatus:
    return PublicDemoStatus(
        enabled=settings.deployment_profile == DEPLOYMENT_PROFILE_PUBLIC_DEMO,
        profile=(
            "public_demo"
            if settings.deployment_profile == DEPLOYMENT_PROFILE_PUBLIC_DEMO
            else "private"
        ),
        max_bytes=settings.public_demo_max_bytes,
        max_lines=settings.public_demo_max_lines,
        session_timeout_seconds=settings.public_demo_session_timeout_seconds,
        allowed_extensions=_allowed_extensions(),
        available_views=list(PUBLIC_VIEWS),
    )


@router.post("/analyze", response_model=PublicDemoAnalysisResponse)
async def analyze_public_demo(
    payload: PublicDemoAnalyzeRequest,
) -> PublicDemoAnalysisResponse:
    _require_public_demo()
    filename, text = _validate_payload(payload.filename, payload.text)
    return await _run_guarded_analysis(filename, text)


@router.post("/analyze/sample/{sample_id}", response_model=PublicDemoAnalysisResponse)
async def analyze_public_sample(sample_id: str) -> PublicDemoAnalysisResponse:
    _require_public_demo()
    relative_path = SAMPLE_INPUTS.get(sample_id)
    if relative_path is None:
        raise HTTPException(status_code=404, detail="Public demo sample was not found.")
    path = _project_root() / relative_path
    if not path.exists():
        raise HTTPException(status_code=404, detail="Public demo sample file was not found.")
    filename, text = _validate_payload(path.name, path.read_text(encoding="utf-8"))
    return await _run_guarded_analysis(filename, text)


@router.post("/report/incident", response_model=ReportResponse)
def public_incident_report(request: ReportRequest) -> ReportResponse:
    _require_public_demo()
    sanitized = request.model_copy(update={"assistant_summary": None})
    return render_incident_markdown_report(sanitized)


@router.post("/report/case", response_model=ReportResponse)
def public_case_report(request: CaseReportRequest) -> ReportResponse:
    _require_public_demo()
    sanitized = request.model_copy(update={"assistant_summary": None})
    return render_case_markdown_report(sanitized)


async def _run_guarded_analysis(
    filename: str,
    text: str,
) -> PublicDemoAnalysisResponse:
    if not PUBLIC_DEMO_CONCURRENCY.try_acquire(settings.public_demo_max_concurrency):
        raise HTTPException(
            status_code=429,
            detail="Public demo is busy. Retry after the active analyses finish.",
        )
    release_immediately = True
    try:
        loop = asyncio.get_running_loop()
        analysis_future = loop.run_in_executor(None, _analyze_stateless, filename, text)
        try:
            result = await asyncio.wait_for(
                asyncio.shield(analysis_future),
                timeout=settings.public_demo_timeout_seconds,
            )
        except TimeoutError as exc:
            release_immediately = False
            analysis_future.add_done_callback(_release_background_analysis)
            raise HTTPException(
                status_code=504,
                detail="Public demo analysis exceeded the execution timeout.",
            ) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        if release_immediately:
            PUBLIC_DEMO_CONCURRENCY.release()

    return PublicDemoAnalysisResponse(
        analysis=result,
        session_timeout_seconds=settings.public_demo_session_timeout_seconds,
    )


def _release_background_analysis(future: asyncio.Future[AnalysisResult]) -> None:
    if not future.cancelled():
        future.exception()
    PUBLIC_DEMO_CONCURRENCY.release()


def _analyze_stateless(filename: str, text: str) -> AnalysisResult:
    result = analyze_text(
        text=text,
        filename=filename,
        rules_root=_project_root() / "packages/rules",
    )
    raw_lines = build_raw_lines_from_text(text, result.source_id)
    result.entities = build_entities(
        None,
        result.events,
        result.findings,
        result.incidents,
    )
    result.evidence_integrity = verify_analysis_integrity(
        result,
        raw_lines,
        origin="upload",
    )
    result.analysis_id = None
    return result


def _validate_payload(filename: str, text: str) -> tuple[str, str]:
    normalized_filename = Path(filename).name
    if normalized_filename != filename or normalized_filename in {"", ".", ".."}:
        raise HTTPException(status_code=400, detail="Filename must not contain a path.")
    extension = Path(normalized_filename).suffix.lower()
    allowed = set(_allowed_extensions())
    if extension not in allowed:
        raise HTTPException(
            status_code=415,
            detail=(
                "Unsupported public demo extension. Allowed extensions: "
                + ", ".join(sorted(allowed))
                + "."
            ),
        )

    byte_count = len(text.encode("utf-8"))
    if byte_count > settings.public_demo_max_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                "Public demo upload exceeds the "
                f"{settings.public_demo_max_bytes} byte limit."
            ),
        )
    line_count = text.count("\n") + (0 if text.endswith("\n") else 1)
    if line_count > settings.public_demo_max_lines:
        raise HTTPException(
            status_code=413,
            detail=(
                "Public demo upload exceeds the "
                f"{settings.public_demo_max_lines} line limit."
            ),
        )
    if "\x00" in text:
        raise HTTPException(status_code=400, detail="Public demo accepts text logs only.")
    control_count = sum(
        1 for character in text if ord(character) < 32 and character not in "\n\r\t"
    )
    if control_count > max(1, len(text) // 100):
        raise HTTPException(
            status_code=400,
            detail="Public demo input contains too many control characters.",
        )
    return normalized_filename, text


def _allowed_extensions() -> list[str]:
    return sorted(
        {
            extension.strip().lower()
            for extension in settings.public_demo_allowed_extensions.split(",")
            if extension.strip()
        }
    )


def _require_public_demo() -> None:
    if settings.deployment_profile != DEPLOYMENT_PROFILE_PUBLIC_DEMO:
        raise HTTPException(status_code=404, detail="Public demo is not enabled.")


def _project_root() -> Path:
    return Path(__file__).resolve().parents[4]
