from fastapi.testclient import TestClient

from tracehawk_api.main import app


def test_rule_library_exposes_detection_learning_context() -> None:
    client = TestClient(app)

    response = client.get("/api/rules/library")

    assert response.status_code == 200
    body = response.json()
    assert body["rule_count"] >= 40
    assert "Auth" in body["categories"]
    ssh_rule = next(rule for rule in body["rules"] if rule["id"] == "ssh-bruteforce-001")
    assert ssh_rule["title"] == "SSH brute force attempt"
    assert ssh_rule["severity"] == "high"
    assert ssh_rule["mitre_technique_id"] == "T1110.001"
    assert ssh_rule["look_for"]
    assert ssh_rule["false_positives"]
    assert ssh_rule["recommendations"]
    assert ssh_rule["correlation"]["family"] == "credential_access"
    assert ssh_rule["correlation"]["incident_title"] is None
    assert "ssh_failures" in ssh_rule["correlation"]["behaviors"]
    assert ssh_rule["correlation"]["entity_fields"] == ["source_ip", "username"]
