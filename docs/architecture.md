# Architecture

Architecture decision records:

- [Confidence-ranked parser routing](adr/0001-confidence-ranked-parser-routing.md)
- [Transparent additive correlation scoring](adr/0002-transparent-correlation-scoring.md)
- [LLM explanation boundary](adr/0003-llm-explanation-boundary.md)

The executable review path is documented in the
[technical walkthrough](technical-walkthrough.md).

```text
Browser / API client
↓
FastAPI application
↓
Upload validation and rate limiting
↓
Parser layer
  - Linux SSH auth logs
  - nginx/apache-style access logs
  - Windows Event CSV exports
  - firewall deny/drop text logs
  - Zeek JSON / TSV logs
  - Suricata EVE JSON logs
  - live interface packet metadata
  - confidence-ranked selection across a stratified file sample
  - per-line parser routing for mixed text dumps
↓
Detection rule engine
↓
Evidence extraction
↓
Entity correlation
↓
Incident grouping
↓
Grounded analyst summary
↓
SOC dashboard + JSON / Markdown / PDF report
```

## Design Principles

- Deterministic detections first, AI-style summaries second.
- Every finding must include evidence lines and affected entities.
- Reports must separate observed evidence from recommended analyst action.
- Demo data must be sanitized and repeatable.
- Deployment must remain Docker-first and portable across Azure, VPS, and self-hosted environments.
- Specific parsers must outrank generic fallbacks, and mixed input must preserve parser provenance on
  every parsed event.

## Core Objects

```text
AnalysisResult
├── Finding
│   ├── rule_id
│   ├── severity
│   ├── confidence
│   ├── evidence[]
│   ├── entities[]
│   ├── MITRE ATT&CK mapping
│   └── recommended actions
├── Incident
│   └── correlated findings by shared entities
└── AnalystSummary
    └── grounded narrative built from extracted findings
```

## Current Deployment

```text
Azure Container Registry
↓
Azure Container Apps
↓
Built-in Google authentication
↓
Application-level email allowlist
```

The app does not persist uploaded files. It persists local analysis results, incidents, and evidence
metadata in SQLite so an analyst can reopen runs and export reports without retaining original
uploaded files.
