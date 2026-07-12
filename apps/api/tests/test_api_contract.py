from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/generate_api_contract.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_api_contract", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CORE_BROWSER_SCHEMAS = {
    "AnalysisResult",
    "AnalystNote",
    "AssistantResponse",
    "AssistantSettings",
    "EvidenceIntegritySummary",
    "Finding",
    "Incident",
    "ReportResponse",
    "RuleLibraryItem",
}


def test_checked_in_api_contract_matches_fastapi_schema() -> None:
    generator = _load_generator()

    assert generator.check_contract() == []


def test_browser_contract_contains_core_response_models() -> None:
    generator = _load_generator()
    document = json.loads(generator.OPENAPI_PATH.read_text(encoding="utf-8"))
    schemas = document["components"]["schemas"]
    assert CORE_BROWSER_SCHEMAS <= schemas.keys()

    generated_types = generator.TYPESCRIPT_PATH.read_text(encoding="utf-8")
    for schema_name in CORE_BROWSER_SCHEMAS:
        assert f"export type {schema_name} =" in generated_types
