"""Stable report-service API backed by format-specific renderer modules."""

from .html import render_incident_html_report
from .markdown import render_case_markdown_report, render_incident_markdown_report
from .models import CaseReportRequest, ReportRedactionOptions, ReportRequest, ReportResponse
from .pdf import render_case_pdf_report, render_incident_pdf_report

__all__ = [
    "CaseReportRequest",
    "ReportRedactionOptions",
    "ReportRequest",
    "ReportResponse",
    "render_case_markdown_report",
    "render_case_pdf_report",
    "render_incident_html_report",
    "render_incident_markdown_report",
    "render_incident_pdf_report",
]
