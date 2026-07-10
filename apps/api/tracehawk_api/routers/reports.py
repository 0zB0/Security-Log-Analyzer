from fastapi import APIRouter

from tracehawk_api.services.reports import (
    CaseReportRequest,
    ReportRequest,
    ReportResponse,
    render_case_markdown_report,
    render_case_pdf_report,
    render_incident_html_report,
    render_incident_markdown_report,
    render_incident_pdf_report,
)


router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("/incident", response_model=ReportResponse)
def incident_report(request: ReportRequest, format: str = "markdown") -> ReportResponse:
    if format == "html":
        return render_incident_html_report(request)
    if format == "pdf":
        return render_incident_pdf_report(request)
    return render_incident_markdown_report(request)


@router.post("/case", response_model=ReportResponse)
def case_report(request: CaseReportRequest, format: str = "markdown") -> ReportResponse:
    if format == "pdf":
        return render_case_pdf_report(request)
    return render_case_markdown_report(request)
