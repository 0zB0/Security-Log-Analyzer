#!/usr/bin/env python3
from __future__ import annotations

from fastapi.testclient import TestClient
from tracehawk_api.main import app


def main() -> int:
    client = TestClient(app)
    status_response = client.get("/api/assistant/status")
    status_response.raise_for_status()
    status = status_response.json()

    if not status.get("enabled"):
        print("smoke_ollama=skip")
        print(f"provider={status.get('provider')}")
        print(f"model={status.get('model')}")
        print(f"error={status.get('error')}")
        return 0

    with open("packages/test-scenarios/auth-ssh-compromise/input.log", "rb") as handle:
        analysis_response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-bruteforce.log", handle, "text/plain")},
        )
    analysis_response.raise_for_status()
    analysis = analysis_response.json()

    explain_response = client.post(
        "/api/assistant/explain",
        json={
            "incident": analysis["incidents"][0],
            "findings": analysis["findings"],
            "evidence": analysis["evidence"],
            "question": "Summarize the incident and next checks.",
        },
    )
    explain_response.raise_for_status()
    explanation = explain_response.json()
    assert explanation["provider"] in {"ollama", "mock"}
    if explanation["provider"] == "mock":
        assert any(
            "Ollama response was unavailable or invalid" in guardrail
            for guardrail in explanation["guardrails"]
        )
    assert explanation["summary"]
    assert set(explanation["evidence_references"]).issubset(
        {line["line_number"] for line in analysis["evidence"]}
    )

    print("smoke_ollama=ok")
    print(f"model={explanation['model']}")
    print(f"evidence_refs={explanation['evidence_references'][:5]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
