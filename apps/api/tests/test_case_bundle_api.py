from base64 import b64decode
from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient
from pypdf import PdfReader

from tracehawk_api.main import app


ROOT = Path(__file__).resolve().parents[3]
REAL_LAB_ROOT = ROOT / "docs/proof-pack/v0.4.1-real-lab/engine-output"


def test_real_lab_case_sample_correlates_zeek_and_suricata_exports() -> None:
    client = TestClient(app)

    response = client.get("/api/analyze/case-sample/real-lab")

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"].startswith("analysis:")
    assert body["parser"] == "case_bundle"
    assert body["raw_line_count"] >= 60
    assert body["parsed_event_count"] >= 60
    assert body["finding_count"] >= 13
    assert body["incident_count"] >= 2
    assert {source["parser"] for source in body["sources"]} == {"zeek_tsv", "suricata_eve"}
    assert {source["filename"] for source in body["sources"]} == {
        "conn.log",
        "dns.log",
        "http.log",
        "eve.json",
    }
    assert {link["link_type"] for link in body["cross_source_links"]} >= {
        "dns_query_match",
        "http_path_match",
        "flow_match",
    }
    evidence_ids = {line["id"] for line in body["evidence"]}
    first_link = body["cross_source_links"][0]
    assert first_link["source_raw_line_id"] in evidence_ids
    assert first_link["target_raw_line_id"] in evidence_ids
    assert first_link["source_event_type"].startswith("suricata_")
    assert first_link["target_event_type"].startswith("zeek_")
    assert first_link["match_value"]
    assert {
        "zeek-conn-port-scan-001",
        "zeek-dns-burst-001",
        "zeek-http-sensitive-path-001",
        "suricata-c2-category-001",
        "suricata-scan-signature-001",
    } <= {finding["rule_id"] for finding in body["findings"]}
    assert body["incidents"][0]["score"] >= body["incidents"][1]["score"]
    assert body["incidents"][0]["score"] == 100
    assert body["incidents"][0]["score_breakdown"]["sequence_quality"] == 25
    assert body["incidents"][0]["score_breakdown"]["time_window_proximity"] == 10
    assert body["incidents"][0]["score_breakdown"]["cross_source_corroboration"] == 18
    assert body["incidents"][0]["score_breakdown"]["rule_family_diversity"] > 0
    assert body["incidents"][1]["score_breakdown"]["sequence_quality"] == 0
    assert body["incidents"][0]["score_breakdown"]["sequence_quality"] > body["incidents"][1]["score_breakdown"]["sequence_quality"]
    assert any("Sequence quality" in item for item in body["incidents"][0]["score_rationale"])
    assert any("Cross-source corroboration" in item for item in body["incidents"][0]["score_rationale"])
    assert body["case_quality"]["strongest_incident_id"] == body["incidents"][0]["id"]
    assert body["case_quality"]["strongest_incident_score"] == body["incidents"][0]["score"]
    assert body["case_quality"]["sequence_backed_incident_count"] >= 1
    assert body["case_quality"]["cross_source_corroborated_incident_count"] >= 2
    assert body["case_quality"]["total_cross_source_links"] == len(body["cross_source_links"])
    assert body["case_quality"]["top_scoring_reason"].startswith("Sequence quality:")
    assert "Cross-source corroboration" in body["incidents"][0]["summary"]
    assert any(
        phrase in body["incidents"][0]["summary"]
        for phrase in (
            "A DNS burst was followed by a C2 indicator or high-severity alert",
            "An alert burst included high-severity Suricata evidence",
            "Scan activity was followed by sensitive HTTP access",
        )
    )
    assert body["entities"]
    assert any(entity["entity_type"] == "ip" for entity in body["entities"])
    assert any(entity["incident_ids"] for entity in body["entities"])


def test_case_entities_are_persisted_and_readable_by_analysis_id() -> None:
    client = TestClient(app)
    analysis_response = client.get("/api/analyze/case-sample/real-lab")
    assert analysis_response.status_code == 200
    analysis = analysis_response.json()

    entities_response = client.get(f"/api/entities?analysis_id={analysis['analysis_id']}")

    assert entities_response.status_code == 200
    entities = entities_response.json()
    assert entities
    assert entities[0]["risk_score"] >= entities[-1]["risk_score"]
    assert {entity["id"] for entity in entities} == {entity["id"] for entity in analysis["entities"]}
    assert any(entity["entity_type"] == "ip" and entity["finding_ids"] for entity in entities)
    detail_response = client.get(f"/api/entities/{entities[0]['id']}")
    assert detail_response.status_code == 200
    assert detail_response.json()["id"] == entities[0]["id"]


def test_mitre_summary_groups_case_findings_by_tactic_and_technique() -> None:
    client = TestClient(app)
    analysis_response = client.get("/api/analyze/case-sample/real-lab")
    assert analysis_response.status_code == 200
    analysis_id = analysis_response.json()["analysis_id"]

    response = client.get(f"/api/mitre/summary/{analysis_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"] == analysis_id
    assert body["finding_count"] >= 13
    assert body["technique_count"] >= 5
    assert "Command and Control" in body["tactics"]
    assert any(technique["technique_id"] == "T1071" for technique in body["techniques"])
    assert all(technique["finding_ids"] for technique in body["techniques"])


def test_case_bundle_upload_accepts_multiple_real_engine_exports() -> None:
    client = TestClient(app)
    paths = [
        REAL_LAB_ROOT / "zeek/conn.log",
        REAL_LAB_ROOT / "zeek/dns.log",
        REAL_LAB_ROOT / "zeek/http.log",
        REAL_LAB_ROOT / "suricata/eve.json",
    ]

    handles = [path.open("rb") for path in paths]
    try:
        response = client.post(
            "/api/analyze/case-bundle",
            files=[
                ("files", (path.name, handle, "text/plain"))
                for path, handle in zip(paths, handles, strict=True)
            ],
        )
    finally:
        for handle in handles:
            handle.close()

    assert response.status_code == 200
    body = response.json()
    assert body["parser"] == "case_bundle"
    assert len(body["sources"]) == 4
    assert body["cross_source_links"]
    assert body["analysis_id"].startswith("analysis:")


def test_case_report_renders_markdown_and_pdf() -> None:
    client = TestClient(app)
    analysis_response = client.get("/api/analyze/case-sample/real-lab")
    assert analysis_response.status_code == 200
    analysis = analysis_response.json()

    markdown_response = client.post(
        "/api/reports/case",
        json={
            "analysis": analysis,
            "assistant_summary": "Real lab case summary.",
        },
    )
    assert markdown_response.status_code == 200
    markdown = markdown_response.json()
    assert markdown["format"] == "markdown"
    assert markdown["filename"].endswith(".md")
    assert "# TraceHawk Case Report" in markdown["content"]
    assert "Real lab case summary." in markdown["content"]
    assert "Case Quality Summary" in markdown["content"]
    assert "Sequence-backed incidents" in markdown["content"]
    assert "Top scoring reason" in markdown["content"]
    assert "Cross-Source Links" in markdown["content"]
    assert "Scoring Rationale" in markdown["content"]
    assert "Sequence Quality" in markdown["content"]
    assert "Cross-source corroboration" in markdown["content"]
    assert "suricata-c2-category-001" in markdown["content"]

    pdf_response = client.post(
        "/api/reports/case?format=pdf",
        json={
            "analysis": analysis,
            "assistant_summary": "Real lab case summary.",
        },
    )
    assert pdf_response.status_code == 200
    pdf = pdf_response.json()
    pdf_bytes = b64decode(pdf["content"])
    reader = PdfReader(BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    assert pdf["format"] == "pdf"
    assert pdf["filename"].endswith(".pdf")
    assert pdf_bytes.startswith(b"%PDF")
    assert len(reader.pages) >= 3
    assert "TraceHawk Case Report" in text
    assert "Case Quality Summary" in text
    assert "Sequence-backed" in text
    assert "Top scoring reason" in text
    assert "Cross-Source Links" in text
    assert "Scoring Rationale" in text
    assert "Sequence Quality" in text


def test_case_report_redacts_case_evidence_and_links() -> None:
    client = TestClient(app)
    analysis_response = client.get("/api/analyze/case-sample/real-lab")
    assert analysis_response.status_code == 200
    analysis = analysis_response.json()

    report_response = client.post(
        "/api/reports/case",
        json={
            "analysis": analysis,
            "assistant_summary": "Host 10.20.0.25 reached 203.0.113.80.",
            "redaction": {"enabled": True},
        },
    )

    assert report_response.status_code == 200
    content = report_response.json()["content"]
    assert "10.20.0.25" not in content
    assert "203.0.113.80" not in content
    assert "[REDACTED_IP]" in content
    assert "Evidence By Source" in content
    assert "Correlation Method" in content
    assert "raw=" not in content.lower()
