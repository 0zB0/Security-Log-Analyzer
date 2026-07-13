.PHONY: check-structure docs-check docs-audit docs-audit-check lock-check api-contract api-contract-check tree test test-scenarios detection-quality detection-quality-check iot23-evaluation benchmark-smoke benchmark benchmark-scale lint typecheck api-dev web-dev web-test web-build web-e2e compose-check smoke-live smoke-ollama smoke-reports smoke-ui smoke-azure-public real-lab-proof security-scan sbom release-assets verify-all

check-structure:
	@test -f local-soc-assistant-architecture.md
	@test -d apps/api/tracehawk_api
	@test -d apps/web/src
	@test -d packages/rules
	@test -d packages/sample-data
	@test -d docs
	@echo "TraceHawk scaffold OK"

docs-check:
	@.venv/bin/python tools/check_markdown_links.py
	@.venv/bin/python tools/check_docs_structure.py

docs-audit:
	@.venv/bin/python tools/audit_markdown.py

docs-audit-check:
	@.venv/bin/python tools/audit_markdown.py --check

lock-check:
	@.venv/bin/uv pip compile apps/api/pyproject.toml --extra dev --python-version 3.12 --universal --quiet -o /tmp/tracehawk-requirements.lock
	@tail -n +3 apps/api/requirements.lock > /tmp/tracehawk-requirements.expected
	@tail -n +3 /tmp/tracehawk-requirements.lock > /tmp/tracehawk-requirements.actual
	@cmp -s /tmp/tracehawk-requirements.expected /tmp/tracehawk-requirements.actual
	@npm --prefix apps/web ci --ignore-scripts --dry-run >/dev/null
	@echo "Dependency locks OK"

api-contract:
	@.venv/bin/python tools/generate_api_contract.py

api-contract-check:
	@.venv/bin/python tools/generate_api_contract.py --check

tree:
	@find . -path ./.git -prune -o -maxdepth 4 -type f -print | sort

test:
	@.venv/bin/python -m pytest apps/api/tests --cov=tracehawk_api --cov-report=term --cov-fail-under=85 -W error -q

test-scenarios:
	@.venv/bin/python -m pytest apps/api/tests/test_scenarios.py -q

detection-quality:
	@.venv/bin/python tools/evaluate_detection_quality.py

detection-quality-check:
	@.venv/bin/python tools/evaluate_detection_quality.py --check

iot23-evaluation:
	@test -n "$(IOT23_MALICIOUS)" -a -n "$(IOT23_BENIGN)"
	@.venv/bin/python tools/evaluate_iot23.py --input "$(IOT23_MALICIOUS)" --benign-input "$(IOT23_BENIGN)"

benchmark-smoke:
	@.venv/bin/python tools/benchmark_analysis.py --profile smoke --check

benchmark:
	@.venv/bin/python tools/benchmark_analysis.py --profile full

benchmark-scale:
	@.venv/bin/python tools/benchmark_analysis.py --profile scale --check

lint:
	@.venv/bin/python -m ruff check --no-cache apps/api/tracehawk_api apps/api/migrations apps/api/tests tools

typecheck:
	@cd apps/api && "$(CURDIR)/.venv/bin/python" -m mypy

api-dev:
	@.venv/bin/python -m uvicorn tracehawk_api.main:app --reload --app-dir apps/api --host 127.0.0.1 --port 8000

web-dev:
	@npm --prefix apps/web run dev

web-test:
	@npm --prefix apps/web run test:coverage

web-build:
	@npm --prefix apps/web run build

web-e2e:
	@npm --prefix apps/web run test:e2e
	@npm --prefix apps/web run test:e2e:public

compose-check:
	@test "$$(docker compose --profile production config --services)" = "tracehawk"
	@test "$$(docker compose --profile app config --services | tr '\n' ' ')" = "api web "
	@test "$$(docker compose --profile collectors config --services)" = "syslog-collector"
	@test "$$(docker compose --profile public-demo config --services)" = "public-demo"
	@echo "Docker Compose config OK"

smoke-live:
	@.venv/bin/python tools/smoke_live.py

smoke-ollama:
	@.venv/bin/python tools/smoke_ollama.py

smoke-reports:
	@.venv/bin/python tools/smoke_reports.py

smoke-ui:
	@.venv/bin/python tools/smoke_ui.py

smoke-azure-public:
	@.venv/bin/python tools/smoke_azure_public.py

real-lab-proof:
	@.venv/bin/python tools/run_real_lab_proof.py

security-scan:
	@.venv/bin/pip-audit --progress-spinner off
	@npm --prefix apps/web audit --omit=dev --audit-level=high
	@docker run --rm -v "$(CURDIR):/repo" -w /repo zricethezav/gitleaks:v8.30.1 git --no-banner --redact .
	@docker run --rm -v "$(CURDIR):/src" -w /src semgrep/semgrep:1.164.0 semgrep scan --config p/python --config p/typescript --exclude-rule python.django.security.injection.raw-html-format.raw-html-format --error apps/api/tracehawk_api apps/api/migrations apps/web/src tools

sbom:
	@.venv/bin/cyclonedx-py environment .venv/bin/python --pyproject apps/api/pyproject.toml --output-reproducible --of JSON -o gl-sbom-python.cdx.json
	@npm --prefix apps/web sbom --sbom-format cyclonedx > gl-sbom-web.cdx.json

release-assets:
	@.venv/bin/python tools/generate_release_assets.py
	@.venv/bin/python -m pytest apps/api/tests/test_proof_assets.py -q

verify-all: check-structure docs-check lock-check api-contract-check test lint typecheck web-test web-build web-e2e compose-check test-scenarios detection-quality-check benchmark-smoke smoke-live smoke-ollama smoke-reports smoke-ui
	@echo "TraceHawk local verification OK"
