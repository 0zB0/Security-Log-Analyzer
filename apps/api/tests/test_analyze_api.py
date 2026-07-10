from datetime import UTC, datetime, timedelta
from pathlib import Path
from hashlib import sha256

from fastapi.testclient import TestClient
from sqlalchemy import update

from tracehawk_api.database import AnalysisRunRecord, SessionLocal
from tracehawk_api.main import app
from tracehawk_api.services.correlation import correlate_incidents
from tracehawk_api.services.detection import run_detection
from tracehawk_api.services.live import parse_tshark_fields_line
from tracehawk_api.services.rules import load_rules


ROOT = Path(__file__).resolve().parents[3]


def test_analyze_upload_returns_findings_and_evidence() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"

    with sample.open("rb") as file:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-bruteforce.log", file, "text/plain")},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"].startswith("analysis:")
    assert body["parser"] == "linux_auth"
    assert body["raw_line_count"] == 12
    assert body["parsed_event_count"] == 12
    assert body["finding_count"] == 4
    assert body["incident_count"] == 1

    rules = {finding["rule_id"]: finding for finding in body["findings"]}
    assert set(rules) == {
        "ssh-bruteforce-001",
        "ssh-compromise-sequence-001",
        "ssh-success-after-failures-001",
        "sudo-user-management-001",
    }
    assert rules["ssh-bruteforce-001"]["mitre"]["technique_id"] == "T1110.001"
    assert rules["ssh-success-after-failures-001"]["severity"] == "critical"
    assert body["incidents"][0]["title"] == "Possible SSH credential compromise"
    assert body["incidents"][0]["severity"] == "critical"
    assert len(body["incidents"][0]["finding_ids"]) == 4
    assert "ip:198.51.100.10" in body["incidents"][0]["entities"]
    assert "T1136.001" in body["incidents"][0]["mitre_techniques"]
    assert len(body["evidence"]) == 12
    assert body["evidence"][0]["raw_text"].startswith("Jul 05 10:02:11")


def test_analyze_demo_returns_sample_findings() -> None:
    client = TestClient(app)

    response = client.get("/api/analyze/demo")

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"].startswith("analysis:")
    assert body["parser"] == "linux_auth"
    assert body["finding_count"] == 4
    assert body["incident_count"] == 1
    assert body["incidents"][0]["title"] == "Possible SSH credential compromise"


def test_analyze_sample_returns_allowlisted_sample() -> None:
    client = TestClient(app)

    response = client.get("/api/analyze/sample/suricata-c2-http-dns")

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"].startswith("analysis:")
    assert body["parser"] == "suricata_eve"
    assert body["finding_count"] == 4
    assert body["incident_count"] == 1
    assert {finding["rule_id"] for finding in body["findings"]} == {
        "suricata-c2-category-001",
        "suricata-dns-burst-001",
        "suricata-high-severity-alert-001",
        "suricata-http-sensitive-path-001",
    }


def test_analyze_sample_rejects_unknown_sample() -> None:
    client = TestClient(app)

    response = client.get("/api/analyze/sample/unknown")

    assert response.status_code == 404
    assert response.json()["detail"] == "Sample was not found."


def test_analyze_upload_persists_run_and_incidents() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"

    with sample.open("rb") as file:
        upload_response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-bruteforce.log", file, "text/plain")},
        )

    assert upload_response.status_code == 200
    analysis_id = upload_response.json()["analysis_id"]

    runs_response = client.get("/api/analyze/runs")
    assert runs_response.status_code == 200
    runs = runs_response.json()
    assert any(run["id"] == analysis_id for run in runs)

    detail_response = client.get(f"/api/analyze/runs/{analysis_id}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["finding_count"] == 4
    assert detail["incident_count"] == 1
    assert detail["incidents"][0]["title"] == "Possible SSH credential compromise"
    assert len(detail["evidence"]) == 12

    incidents_response = client.get(f"/api/analyze/incidents?analysis_id={analysis_id}")
    assert incidents_response.status_code == 200
    assert any(
        incident["title"] == "Possible SSH credential compromise"
        for incident in incidents_response.json()
    )


def test_analyst_notes_crud_is_scoped_to_analysis_incident() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"

    with sample.open("rb") as file:
        upload_response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-bruteforce.log", file, "text/plain")},
        )
    assert upload_response.status_code == 200
    analysis = upload_response.json()
    analysis_id = analysis["analysis_id"]
    incident_id = analysis["incidents"][0]["id"]

    create_response = client.post(
        f"/api/notes/incidents/{incident_id}",
        json={
            "analysis_id": analysis_id,
            "body": "Confirmed suspicious SSH sequence.",
            "note_type": "decision",
        },
    )
    assert create_response.status_code == 200
    note = create_response.json()
    assert note["analysis_id"] == analysis_id
    assert note["incident_id"] == incident_id
    assert note["note_type"] == "decision"

    list_response = client.get(f"/api/notes/incidents/{incident_id}?analysis_id={analysis_id}")
    assert list_response.status_code == 200
    assert note["id"] in [item["id"] for item in list_response.json()]

    patch_response = client.patch(
        f"/api/notes/{note['id']}",
        json={"body": "Escalated to follow-up review.", "note_type": "follow_up"},
    )
    assert patch_response.status_code == 200
    assert patch_response.json()["note_type"] == "follow_up"
    assert patch_response.json()["body"] == "Escalated to follow-up review."

    delete_response = client.delete(f"/api/notes/{note['id']}")
    assert delete_response.status_code == 200
    assert delete_response.json() == {"deleted": True}

    missing_response = client.post(
        "/api/notes/incidents/incident:missing",
        json={"analysis_id": analysis_id, "body": "Should not attach."},
    )
    assert missing_response.status_code == 404


def test_retention_exports_previews_and_purges_raw_logs() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"

    with sample.open("rb") as file:
        upload_response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-bruteforce.log", file, "text/plain")},
        )
    assert upload_response.status_code == 200
    analysis = upload_response.json()
    analysis_id = analysis["analysis_id"]

    export_response = client.get(f"/api/retention/exports/analysis/{analysis_id}")
    assert export_response.status_code == 200
    export = export_response.json()
    assert export["manifest"]["raw_line_count"] == 12
    assert export["raw_lines"][0]["content_hash"]

    preview_response = client.post(
        "/api/retention/preview",
        json={"mode": "purge_raw_keep_findings", "days": 30},
    )
    assert preview_response.status_code == 200
    preview = preview_response.json()
    assert analysis_id in preview["affected_analysis_ids"]
    assert preview["raw_lines_affected"] >= 12

    apply_response = client.post(
        "/api/retention/apply",
        json={"mode": "purge_raw_keep_findings", "days": 30},
    )
    assert apply_response.status_code == 200

    detail_response = client.get(f"/api/analyze/runs/{analysis_id}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["finding_count"] == 4
    assert detail["incident_count"] == 1
    assert all(line["raw_text"] == "[PURGED_RAW_LOG]" for line in detail["evidence"])
    assert all(line["content_hash"] for line in detail["evidence"])


def test_retention_deletes_runs_older_than_policy_window() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"

    with sample.open("rb") as file:
        upload_response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-bruteforce.log", file, "text/plain")},
        )
    assert upload_response.status_code == 200
    analysis_id = upload_response.json()["analysis_id"]

    with SessionLocal() as session:
        session.execute(
            update(AnalysisRunRecord)
            .where(AnalysisRunRecord.id == analysis_id)
            .values(created_at=datetime.now(UTC) - timedelta(days=90))
        )
        session.commit()

    preview_response = client.post(
        "/api/retention/preview",
        json={"mode": "keep_last_n_days", "days": 30},
    )
    assert preview_response.status_code == 200
    assert analysis_id in preview_response.json()["affected_analysis_ids"]

    apply_response = client.post(
        "/api/retention/apply",
        json={"mode": "keep_last_n_days", "days": 30},
    )
    assert apply_response.status_code == 200
    assert client.get(f"/api/analyze/runs/{analysis_id}").status_code == 404


def test_live_snapshot_can_be_persisted_as_analysis_run() -> None:
    client = TestClient(app)
    events = []
    evidence = []

    for index, destination_port in enumerate(range(30000, 30010), start=1):
        raw_text = (
            f"1783539718.{index:06d}\t10.8.0.2\t\t10.0.0.5\t\t52144\t\t"
            f"{destination_port}\t\teth:ip:tcp\t74\tTCP\tclient > {destination_port}"
        )
        raw_line_id = f"interface:wg0:packet:{index}"
        event = parse_tshark_fields_line(raw_line_id, "interface:wg0", raw_text, "wg0")
        assert event is not None
        events.append(event)
        evidence.append(
            {
                "id": raw_line_id,
                "line_number": index,
                "raw_text": raw_text,
                "content_hash": sha256(raw_text.encode("utf-8")).hexdigest(),
            }
        )

    findings = run_detection(load_rules(ROOT / "packages/rules/network"), events)
    incidents = correlate_incidents(findings, events)
    response = client.post(
        "/api/analyze/live-snapshot",
        json={
            "analysis_id": None,
            "source_id": "interface:wg0",
            "parser": "network_packet",
            "raw_line_count": len(evidence),
            "parsed_event_count": len(events),
            "finding_count": len(findings),
            "incident_count": len(incidents),
            "events": [event.model_dump(mode="json") for event in events],
            "findings": [finding.model_dump(mode="json") for finding in findings],
            "incidents": [incident.model_dump(mode="json") for incident in incidents],
            "evidence": evidence,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"].startswith("analysis:")
    assert body["parser"] == "network_packet"
    assert body["raw_line_count"] == 10
    assert body["parsed_event_count"] == 10
    assert body["finding_count"] >= 1
    assert body["incidents"]
    assert body["source_id"].startswith("interface:wg0:saved:")
    assert all(line["id"].startswith("analysis-") for line in body["evidence"])

    detail_response = client.get(f"/api/analyze/runs/{body['analysis_id']}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["parser"] == "network_packet"
    assert any(
        finding["rule_id"] == "network-wireguard-port-scan-001"
        for finding in detail["findings"]
    )
    assert detail["evidence"][0]["id"] in detail["findings"][0]["evidence_line_ids"]


def test_analyze_upload_rejects_unsupported_log() -> None:
    client = TestClient(app)

    response = client.post(
        "/api/analyze/upload",
        files={"file": ("notes.txt", b"hello world\nthis is not a supported log\n", "text/plain")},
    )

    assert response.status_code == 422
    assert "No supported parser" in response.json()["detail"]
