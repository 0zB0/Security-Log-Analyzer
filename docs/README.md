# TraceHawk Community Documentation

This is the public documentation hub for the curated TraceHawk community release. GitLab remains
the complete engineering source of truth; this GitHub repository contains the runnable product,
tests, sanitized fixtures, public evidence, and public-safe technical documentation.

## Start Here

- [Product specification](product-spec.md)
- [Engineering portfolio guide](engineering-portfolio-guide.md)
- [System architecture](architecture.md)
- [Event-processing pipeline](event-processing-pipeline.md)
- [Persistence and evidence lifecycle](persistence-evidence-lifecycle.md)
- [Frontend architecture](frontend-architecture.md)
- [Limitations](limitations.md)
- [AI-assisted development disclosure](ai-assisted-development.md)

## Security And Detection

- [Threat model](threat-model.md)
- [Security controls](security.md)
- [Authentication and RBAC](auth-rbac.md)
- [Detection rules](rules.md)
- [Rule authoring](rule-authoring.md)
- [Detection-quality method](detection-quality.md)
- [Incident correlation](correlation.md)
- [Case investigation workflow](case-investigation-workflow.md)

## Ingest Guides

- [Zeek and Suricata](zeek-suricata-ingest.md)
- [Windows Security events](windows-event-ingest.md)
- [CloudTrail](cloudtrail-ingest.md)
- [Kubernetes audit events](kubernetes-audit-ingest.md)
- [WireGuard/interface metadata](wireguard-packet-capture.md)

## Build, Test, And Operate

- [API reference](api.md)
- [Testing strategy](testing-strategy.md)
- [Performance method](performance.md)
- [Self-hosted deployment](deployment-selfhost.md)
- [Operations](operations.md)
- [Technical walkthrough](technical-walkthrough.md)
- [Engineering case studies](engineering-case-studies/)
- [Local LLM privacy model](llm-privacy-model.md)

## Demo And Public Evidence

- [Demo scenario](demo-scenario.md)
- [Demo walkthrough](demo-walkthrough.md)
- [Multi-source real-lab case study](case-study-real-lab.md)
- [Current detection-quality result](proof-pack/current-detection-quality.md)
- [Current IoT-23 evaluation](proof-pack/current-iot23-evaluation.md)
- [Current performance result](proof-pack/current-performance.md)
- [Current scale result](proof-pack/current-scale-performance.md)
- [Public release notes](releases/v0.7.1.md)

## Architecture Decisions

- [Confidence-ranked parser routing](adr/0001-confidence-ranked-parser-routing.md)
- [Transparent additive correlation scoring](adr/0002-transparent-correlation-scoring.md)
- [LLM explanation outside detection authority](adr/0003-llm-explanation-boundary.md)

## Public Boundary

Private deployment configuration, internal CI/CD records, source-only runbooks, and non-public
infrastructure details are intentionally omitted. `PUBLIC_EXPORT.json` records the source commit,
file count, and content digest for each generated community export.

Run `make docs-check` to validate public local links and canonical-document structure.
