.PHONY: check-structure tree test test-scenarios detection-quality detection-quality-check iot23-evaluation benchmark-smoke benchmark lint api-dev web-dev web-build compose-check smoke-live smoke-ollama smoke-reports smoke-ui smoke-azure-public real-lab-proof security-scan sbom release-assets verify-all

check-structure:
	@test -f local-soc-assistant-architecture.md
	@test -d apps/api/tracehawk_api
	@test -d apps/web/src
	@test -d packages/rules
	@test -d packages/sample-data
	@test -d docs
	@echo "TraceHawk scaffold OK"

tree:
	@find . -path ./.git -prune -o -maxdepth 4 -type f -print | sort

test:
	@.venv/bin/python -m pytest apps/api/tests -W error -q

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

lint:
	@.venv/bin/python -m ruff check apps/api/tracehawk_api apps/api/tests tools

api-dev:
	@.venv/bin/python -m uvicorn tracehawk_api.main:app --reload --app-dir apps/api --host 0.0.0.0 --port 8000

web-dev:
	@npm --prefix apps/web run dev

web-build:
	@npm --prefix apps/web run build

compose-check:
	@docker compose config >/dev/null
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
	@docker run --rm -v "$(CURDIR):/src" -w /src semgrep/semgrep:1.164.0 semgrep scan --config p/python --config p/typescript --exclude-rule python.django.security.injection.raw-html-format.raw-html-format --error apps/api/tracehawk_api apps/web/src tools

sbom:
	@.venv/bin/cyclonedx-py environment .venv/bin/python --pyproject apps/api/pyproject.toml --output-reproducible --of JSON -o gl-sbom-python.cdx.json
	@npm --prefix apps/web sbom --sbom-format cyclonedx > gl-sbom-web.cdx.json

release-assets:
	@.venv/bin/python tools/generate_release_assets.py
	@.venv/bin/python -m pytest apps/api/tests/test_proof_assets.py -q

verify-all: check-structure test lint web-build compose-check test-scenarios detection-quality-check benchmark-smoke smoke-live smoke-ollama smoke-reports smoke-ui
	@echo "TraceHawk local verification OK"
