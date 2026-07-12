import json
from pathlib import Path
import tomllib

import yaml


ROOT = Path(__file__).resolve().parents[3]


def test_compose_publishes_only_loopback_ports() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))

    for service_name in ("tracehawk", "api", "web"):
        ports = compose["services"][service_name]["ports"]
        assert ports
        assert all(str(port).startswith("127.0.0.1:") for port in ports)


def test_self_host_command_selects_the_production_profile() -> None:
    deployment = (ROOT / "docs/deployment-selfhost.md").read_text(encoding="utf-8")

    assert "docker compose --profile production up --build" in deployment
    assert "Do not change the bind to `0.0.0.0`" in deployment


def test_local_development_commands_bind_to_loopback() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    web_package = (ROOT / "apps/web/package.json").read_text(encoding="utf-8")

    assert "--host 127.0.0.1" in makefile
    assert "vite --host 127.0.0.1" in web_package
    assert "vite preview --host 127.0.0.1" in web_package


def test_public_release_versions_are_aligned() -> None:
    api_project = tomllib.loads(
        (ROOT / "apps/api/pyproject.toml").read_text(encoding="utf-8")
    )
    web_project = json.loads((ROOT / "apps/web/package.json").read_text(encoding="utf-8"))
    release_metadata_path = ROOT / "public/github/export-manifest.json"
    if not release_metadata_path.is_file():
        release_metadata_path = ROOT / "PUBLIC_EXPORT.json"
    release_metadata = json.loads(release_metadata_path.read_text(encoding="utf-8"))
    frontend = (ROOT / "apps/web/src/app/main.tsx").read_text(encoding="utf-8")
    api = (ROOT / "apps/api/tracehawk_api/main.py").read_text(encoding="utf-8")

    assert api_project["project"]["version"] == "0.8.0"
    assert web_project["version"] == "0.8.0"
    assert release_metadata["release"] == "v0.8.0"
    assert "TraceHawk v0.8.0" in frontend
    assert 'version="0.8.0"' in api
    assert '"release": "v0.8.0"' in api
