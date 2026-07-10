from pathlib import Path

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
