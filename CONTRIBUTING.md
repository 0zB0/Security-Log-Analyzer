# Contributing

TraceHawk accepts focused fixes, parser improvements, detection rules, tests, and documentation.

## Development Gate

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip==26.1.2
.venv/bin/python -m pip install --constraint apps/api/requirements.lock -e 'apps/api[dev]'
npm --prefix apps/web ci
make verify-all
```

Read the [technical walkthrough](docs/technical-walkthrough.md) and relevant
[architecture decisions](docs/adr/) before changing parser routing, correlation scoring, or the
local LLM boundary.

Keep detections deterministic and evidence-first. New rules require a positive scenario, a benign
control where practical, MITRE metadata, analyst guidance, and false-positive notes. Do not commit
real logs, credentials, client data, internal infrastructure, or other confidential evidence.

Open a pull request with a concise problem statement, behavioral change, and exact verification
commands. Security reports must follow [SECURITY.md](SECURITY.md), not a public issue.
