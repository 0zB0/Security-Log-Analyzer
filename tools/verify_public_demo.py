#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an isolated stateless public demo.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--attempts", type=int, default=18)
    parser.add_argument("--delay-seconds", type=float, default=5)
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    last_error: Exception | None = None
    for attempt in range(1, args.attempts + 1):
        try:
            result = verify_public_demo(base_url, args.expected_commit)
        except (AssertionError, OSError, ValueError) as exc:
            last_error = exc
            if attempt == args.attempts:
                break
            time.sleep(args.delay_seconds)
        else:
            print(json.dumps(result, sort_keys=True))
            return 0
    assert last_error is not None
    raise RuntimeError(
        f"Public demo verification failed after {args.attempts} attempts: {last_error}"
    )


def verify_public_demo(base_url: str, expected_commit: str) -> dict[str, Any]:
    version_status, version, _ = _request_json(f"{base_url}/api/version")
    assert version_status == 200
    assert version["build_commit"] == expected_commit
    assert version["deployment_profile"] == "public_demo"
    assert version["llm_provider"] == "mock"

    ready_status, ready, _ = _request_json(f"{base_url}/api/health/ready")
    assert ready_status == 200
    assert ready["status"] == "ready"
    assert ready["checks"]["database"] == "disabled"

    status_code, status, status_headers = _request_json(
        f"{base_url}/api/public-demo/status"
    )
    assert status_code == 200
    assert status["enabled"] is True
    assert status["storage"] == "disabled"
    assert status["external_ai"] is False
    _assert_no_store(status_headers)

    private_status, private_body, _ = _request_json(f"{base_url}/api/analyze/runs")
    assert private_status == 404
    assert private_body["detail"] == "Not found"

    payload = {
        "filename": "public-smoke-auth.log",
        "text": SAMPLE.read_text(encoding="utf-8"),
    }
    first_status, first, first_headers = _request_json(
        f"{base_url}/api/public-demo/analyze",
        method="POST",
        payload=payload,
    )
    assert first_status == 200
    assert first["stored"] is False
    assert first["external_ai"] is False
    assert first["analysis"]["analysis_id"] is None
    assert first["analysis"]["parser"] == "linux_auth"
    _assert_no_store(first_headers)

    second_status, second, _ = _request_json(
        f"{base_url}/api/public-demo/analyze",
        method="POST",
        payload=payload,
    )
    assert second_status == 200
    assert second["analysis"]["analysis_id"] is None
    assert second["analysis"]["source_id"] == first["analysis"]["source_id"]

    tutorial_status, _, _ = _request_text(f"{base_url}/tutorial")
    assert tutorial_status == 200

    manifest_status, tutorial_videos, manifest_headers = _request_json(
        f"{base_url}/tutorial-videos/manifest.json"
    )
    assert manifest_status == 200
    assert manifest_headers.get("content-type") == "application/json"
    expected_video_views = {
        "upload",
        "incidents",
        "findings",
        "evidence",
        "entities",
        "mitre",
        "reports",
        "library",
    }
    assert {item["view"] for item in tutorial_videos} == expected_video_views
    for item in tutorial_videos:
        video_status, video_headers = _request_headers(f"{base_url}{item['video']}")
        assert video_status == 200
        assert video_headers.get("content-type") == "video/mp4"
        assert int(video_headers.get("content-length", "0")) > 100_000
        captions_status, captions, captions_headers = _request_text(
            f"{base_url}{item['captions']}"
        )
        assert captions_status == 200
        assert captions.startswith("WEBVTT\n")
        assert captions_headers.get("content-type", "").startswith("text/vtt")

    return {
        "status": "ok",
        "url": base_url,
        "build_commit": version["build_commit"],
        "deployment_profile": version["deployment_profile"],
        "database": ready["checks"]["database"],
        "private_api_status": private_status,
        "stored": first["stored"],
        "external_ai": first["external_ai"],
        "tutorial_video_count": len(tutorial_videos),
    }


def _assert_no_store(headers: dict[str, str]) -> None:
    assert headers.get("cache-control") == "no-store, max-age=0"
    assert headers.get("pragma") == "no-cache"
    assert headers.get("expires") == "0"


def _request_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> tuple[int, Any, dict[str, str]]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "User-Agent": "tracehawk-public-demo-verifier/1",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return (
                response.status,
                json.loads(response.read().decode("utf-8")),
                {key.lower(): value for key, value in response.headers.items()},
            )
    except urllib.error.HTTPError as exc:
        content = exc.read().decode("utf-8")
        return (
            exc.code,
            json.loads(content) if content else {},
            {key.lower(): value for key, value in exc.headers.items()},
        )


def _request_text(url: str) -> tuple[int, str, dict[str, str]]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "tracehawk-public-demo-verifier/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return (
                response.status,
                response.read().decode("utf-8"),
                {key.lower(): value for key, value in response.headers.items()},
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            exc.read().decode("utf-8"),
            {key.lower(): value for key, value in exc.headers.items()},
        )


def _request_headers(url: str) -> tuple[int, dict[str, str]]:
    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "tracehawk-public-demo-verifier/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return (
                response.status,
                {key.lower(): value for key, value in response.headers.items()},
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            {key.lower(): value for key, value in exc.headers.items()},
        )


if __name__ == "__main__":
    raise SystemExit(main())
