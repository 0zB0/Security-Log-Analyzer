#!/usr/bin/env python3
from __future__ import annotations

import re
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urljoin

import httpx

ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> int:
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        ["npm", "--prefix", "apps/web", "run", "dev", "--", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for_vite(base_url, process)
        html = httpx.get(base_url, timeout=5).text
        assert '<div id="root"></div>' in html
        assert "/src/app/main.tsx" in html
        module_paths = re.findall(r'<script type="module" src="([^"]+)"></script>', html)
        assert module_paths
        module_text = ""
        for module_path in module_paths:
            module_response = httpx.get(urljoin(base_url, module_path), timeout=5)
            module_response.raise_for_status()
            module_text += module_response.text
        assert "/src/app/main.tsx" in html
        assert "/src/styles/main.css" in module_text
        css_response = httpx.get(f"{base_url}/src/styles/main.css", timeout=5)
        css_response.raise_for_status()
        assert ".shell" in css_response.text
        workspace_sources = sorted(
            path
            for pattern in ("*.ts", "*.tsx")
            for path in (ROOT / "apps/web/src/features/workspace").glob(pattern)
            if not path.name.endswith((".test.ts", ".test.tsx"))
        )
        app_source = "\n".join(
            [
                (ROOT / "apps/web/src/app/main.tsx").read_text(),
                (ROOT / "apps/web/src/app/workspaceOptions.ts").read_text(),
                *(path.read_text() for path in workspace_sources),
            ]
        )
        assert "async function handleRunDemo()" in app_source
        assert "async function handleRunRealLabCase()" in app_source
        assert "onClick={handleRunDemo}" in app_source
        assert "onClick={handleRunRealLabCase}" in app_source
        assert "CloudTrail IAM risk" in app_source
        assert "Kubernetes audit risk" in app_source
        assert "Windows Security risk" in app_source
        assert "analyzeCaseBundle(files)" in app_source
        assert "generateCaseReport" in app_source
        assert "function CaseLinkDetail" in app_source
        assert "function CaseEvidenceCard" in app_source
        assert "source_raw_line_id" in app_source
        assert "target_raw_line_id" in app_source
        assert '<span className="toolbar-button">Data tier: Evidence</span>' in app_source
        assert '<span className="toolbar-button">Last 24 hours</span>' in app_source
        assert 'setReportFormat("markdown")' in app_source
        assert 'setReportFormat("pdf")' in app_source
        assert "onReportFormatChange" in app_source
        assert 'setSourceMode("interface")' in app_source
        assert "Interface Capture" in app_source
        assert "CAPTURE_PRESETS" in app_source
        assert "liveInterfaceWebSocketUrl(interfaceName, captureFilter)" in app_source
        assert "persistLiveSnapshot(latestSnapshot)" in app_source
        assert "<Save size={16} />" in app_source
        assert "live-snapshot-strip" in app_source
        assert "function DetectionLibrary" in app_source
        assert "Found only" in app_source
        assert "Redact IPs, users, and hosts" in app_source
        assert "Cross-source links" in app_source
        assert "Link evidence" in app_source
        assert "Raw lines" in app_source
        assert "Entity inventory" in app_source
        assert 'activeView === "entities"' in app_source
        assert "Analyst notes" in app_source
        assert "createIncidentNote" in app_source
        assert "Local AI settings" in app_source
        assert "Prompt preview" in app_source
        assert "previewAssistantPrompt" in app_source
        assert "MITRE map" in app_source
        assert "buildMitreGroups" in app_source
        assert "selectedModel" in app_source
        assert "status.installed_models.map" in app_source
        css_source = (ROOT / "apps/web/src/styles/main.css").read_text()
        assert ".sidebar {\n    display: flex;" in css_source
        assert "grid-template-columns: auto 1fr;" in css_source
        assert ".source-status-error" in css_source
        print("smoke_ui=ok")
        print(f"url={base_url}")
        return 0
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def _wait_for_vite(base_url: str, process: subprocess.Popen) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Vite exited early: {process.stderr.read() if process.stderr else ''}")
        try:
            response = httpx.get(base_url, timeout=1)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise TimeoutError("Vite server did not become ready.")


if __name__ == "__main__":
    raise SystemExit(main())
