#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import websockets

ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start_api(port: int, db_path: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env["TRACEHAWK_DB_PATH"] = str(db_path)
    env.setdefault("TRACEHAWK_LLM_PROVIDER", "mock")
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "tracehawk_api.main:app",
            "--app-dir",
            "apps/api",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _wait_for_health(base_url: str, process: subprocess.Popen) -> None:
    deadline = time.time() + 15
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"API exited early: {process.stderr.read() if process.stderr else ''}")
        try:
            response = httpx.get(f"{base_url}/api/health", timeout=1)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise TimeoutError("API health check timed out.")


async def _exercise_live(base_url: str, log_path: Path) -> dict:
    log_path.write_text("")
    ws_url = base_url.replace("http://", "ws://") + (
        f"/api/live/file?path={log_path}&start_at_end=true"
    )
    async with websockets.connect(ws_url) as socket_client:
        first = json.loads(await asyncio.wait_for(socket_client.recv(), timeout=5))
        assert first["message_type"] == "snapshot"
        generator = subprocess.run(
            [
                sys.executable,
                "tools/generate_live_logs.py",
                str(log_path),
                "--scenario",
                "ssh-compromise",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        assert "wrote=12" in generator.stdout

        latest = first
        for _ in range(20):
            latest = json.loads(await asyncio.wait_for(socket_client.recv(), timeout=5))
            if latest["finding_count"] >= 3 and latest["incident_count"] >= 1:
                break
        assert latest["parser"] == "linux_auth"
        assert latest["raw_line_count"] == 12
        assert latest["finding_count"] >= 3
        assert latest["incident_count"] >= 1
        assert latest["evidence"]

        await socket_client.send(json.dumps({"action": "pause"}))
        paused = json.loads(await asyncio.wait_for(socket_client.recv(), timeout=5))
        assert paused["status"] == "paused"
        await socket_client.send(json.dumps({"action": "resume"}))
        resumed = json.loads(await asyncio.wait_for(socket_client.recv(), timeout=5))
        assert resumed["status"] == "active"
        return latest


def main() -> int:
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        process = _start_api(port, tmp / "tracehawk.db")
        try:
            _wait_for_health(base_url, process)
            latest = asyncio.run(_exercise_live(base_url, tmp / "live.log"))
            print("smoke_live=ok")
            print(f"parser={latest['parser']}")
            print(f"findings={latest['finding_count']}")
            print(f"incidents={latest['incident_count']}")
            return 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    raise SystemExit(main())
