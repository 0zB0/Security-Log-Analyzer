from html import escape

from tracehawk_api.models.domain import Incident
from tracehawk_api.services.analysis import AnalysisResult


def _score_component_label(component: str) -> str:
    return " ".join(part.capitalize() for part in component.split("_"))


def _xml_text(value: str) -> str:
    return escape(value, quote=False)


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
