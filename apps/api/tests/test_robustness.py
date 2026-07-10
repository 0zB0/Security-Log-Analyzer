from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient

from tracehawk_api.main import app
from tracehawk_api.services.analysis import analyze_text


ROOT = Path(__file__).resolve().parents[3]
RULES_ROOT = ROOT / "packages/rules"
AUTH_SAMPLE = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"


def test_pathological_long_line_and_control_characters_fail_safely() -> None:
    payloads = [
        ("long.log", "x" * 500_000),
        ("controls.log", "\x00\x01\x02\n" * 20_000),
        ("broken.jsonl", '{"message": "unterminated"\n' * 10_000),
        ("empty.log", "\n" * 50_000),
    ]

    for filename, text in payloads:
        try:
            result = analyze_text(text=text, filename=filename, rules_root=RULES_ROOT)
        except ValueError as exc:
            assert str(exc) == "No supported parser matched the uploaded log content."
        else:
            assert result.raw_line_count >= 0
            assert result.parsed_event_count <= result.raw_line_count
            assert all(finding.evidence_line_ids for finding in result.findings)


def test_concurrent_independent_analyses_are_deterministic() -> None:
    text = AUTH_SAMPLE.read_text()

    def analyze() -> tuple[int, int, int, tuple[str, ...]]:
        result = analyze_text(text=text, filename="auth.log", rules_root=RULES_ROOT)
        return (
            result.parsed_event_count,
            result.finding_count,
            result.incident_count,
            tuple(finding.rule_id for finding in result.findings),
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        outcomes = list(executor.map(lambda _: analyze(), range(8)))

    assert len(set(outcomes)) == 1
    assert outcomes[0][0:3] == (12, 4, 1)


def test_rejected_upload_does_not_poison_follow_up_analysis() -> None:
    client = TestClient(app)
    rejected = client.post(
        "/api/analyze/upload",
        files={"file": ("invalid.log", b"valid\n\xff\xfe", "text/plain")},
    )
    recovered = client.post(
        "/api/analyze/upload",
        files={"file": ("auth.log", AUTH_SAMPLE.read_bytes(), "text/plain")},
    )

    assert rejected.status_code == 400
    assert recovered.status_code == 200
    assert recovered.json()["parser"] == "linux_auth"
    assert recovered.json()["finding_count"] == 4
