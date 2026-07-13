import json
from pathlib import Path
import tomllib

import yaml


ROOT = Path(__file__).resolve().parents[3]


def test_compose_publishes_only_loopback_ports() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))

    for service_name in ("tracehawk", "public-demo", "api", "web", "syslog-collector"):
        ports = compose["services"][service_name]["ports"]
        assert ports
        assert all(str(port).startswith("127.0.0.1:") for port in ports)


def test_syslog_collector_is_opt_in_and_default_services_expose_no_listener() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    collector = compose["services"]["syslog-collector"]

    assert collector["profiles"] == ["collectors"]
    assert collector["ports"] == [
        "127.0.0.1:5514:5514/udp",
        "127.0.0.1:5514:5514/tcp",
    ]
    for service_name in ("tracehawk", "api", "web"):
        assert all(
            "5514" not in str(port)
            for port in compose["services"][service_name]["ports"]
        )


def test_public_demo_compose_profile_is_stateless_and_capability_reduced() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    demo = compose["services"]["public-demo"]

    assert demo["profiles"] == ["public-demo"]
    assert "volumes" not in demo
    assert demo["read_only"] is True
    assert demo["tmpfs"] == ["/tmp:size=16m,mode=1777"]
    assert demo["environment"]["TRACEHAWK_DEPLOYMENT_PROFILE"] == "public_demo"
    assert demo["environment"]["TRACEHAWK_AUTH_MODE"] == "disabled"
    assert demo["environment"]["TRACEHAWK_LLM_PROVIDER"] == "mock"
    assert demo["environment"]["PUBLIC_DEMO_MAX_BYTES"] == 524288


def test_azure_delivery_assets_do_not_configure_a_syslog_listener() -> None:
    source_only_paths = (
        ROOT / ".gitlab-ci.yml",
        ROOT / "docs/deployment-azure.md",
        ROOT / "tools/verify_deployment.py",
        ROOT / "tools/smoke_azure_public.py",
    )
    present_paths = tuple(path for path in source_only_paths if path.is_file())

    if not present_paths:
        return

    assert present_paths == source_only_paths
    for path in present_paths:
        assert "5514" not in path.read_text(encoding="utf-8")


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
    web_lock = json.loads((ROOT / "apps/web/package-lock.json").read_text(encoding="utf-8"))
    openapi = json.loads(
        (ROOT / "apps/web/src/generated/openapi.json").read_text(encoding="utf-8")
    )
    release_metadata_path = ROOT / "public/github/export-manifest.json"
    if not release_metadata_path.is_file():
        release_metadata_path = ROOT / "PUBLIC_EXPORT.json"
    release_metadata = json.loads(release_metadata_path.read_text(encoding="utf-8"))
    frontend = (ROOT / "apps/web/src/app/main.tsx").read_text(encoding="utf-8")
    version_module = (ROOT / "apps/api/tracehawk_api/version.py").read_text(encoding="utf-8")
    deployment_verifier_path = ROOT / "tools/verify_deployment.py"
    public_smoke_path = ROOT / "tools/smoke_azure_public.py"

    assert api_project["project"]["version"] == "0.10.0"
    assert web_project["version"] == "0.10.0"
    assert web_lock["version"] == "0.10.0"
    assert web_lock["packages"][""]["version"] == "0.10.0"
    assert openapi["info"]["version"] == "0.10.0"
    assert release_metadata["release"] == "v0.10.0"
    assert "TraceHawk v0.10.0" in frontend
    assert 'API_VERSION = "0.10.0"' in version_module
    assert "ARG TRACEHAWK_VERSION=0.10.0" in (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert (ROOT / "docs/releases/v0.10.0.md").is_file()
    assert "RELEASE = f\"v{API_VERSION}\"" in version_module

    public_overlay_release = ROOT / "public/github/docs/releases/v0.10.0.md"
    if (ROOT / "public/github").is_dir():
        assert public_overlay_release.is_file()

    source_only_paths = (deployment_verifier_path, public_smoke_path)
    present_paths = tuple(path for path in source_only_paths if path.is_file())
    if present_paths:
        assert present_paths == source_only_paths
        deployment_verifier = deployment_verifier_path.read_text(encoding="utf-8")
        public_smoke = public_smoke_path.read_text(encoding="utf-8")
        assert "from tracehawk_api.version import API_VERSION, RELEASE" in deployment_verifier
        assert "from tracehawk_api.version import API_VERSION, RELEASE" in public_smoke
        assert '"0.7.1"' not in deployment_verifier
        assert '"v0.7.1"' not in public_smoke
