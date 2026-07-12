# TraceHawk Product Specification

> Audience: product reviewers, engineers, security analysts, and contributors
> Canonical for: product promise, current user, scope, non-goals, and success criteria
> Verified against: TraceHawk v0.9.0

## Product Promise

TraceHawk is a self-hosted SOC assistant for homelabs and small teams that turns logs and
lightweight telemetry into evidence-backed findings, explanations, and reports.

The core contract is:

```text
raw security logs → normalized events → deterministic findings
→ explainable incidents → exact evidence → analyst-ready report
```

TraceHawk is not a generic chatbot over logs. Every finding is produced by deterministic rules and
must point back to concrete evidence. Optional local AI can explain selected evidence but cannot
create, remove, promote, or change a finding.

## Why It Exists

Security logs are noisy, while full SIEM platforms are often too heavy for a homelab, learning
environment, small team, or bounded incident review. TraceHawk provides a smaller workflow for
answering:

- What suspicious activity was observed?
- Which account, IP, host, service, or path was involved?
- Which rule fired and why?
- Which exact log lines support the result?
- Which related findings form an incident?
- What should an analyst verify next?

## Primary Users

- Junior or intermediate security analysts learning investigation workflows.
- Homelab operators reviewing bounded local telemetry.
- Small teams that need an explainable offline-first investigation aid.
- Technical reviewers evaluating security, backend, frontend, testing, and DevSecOps decisions.

TraceHawk assumes the user remains responsible for validating findings and has authorization to
process the supplied logs or packet metadata.

## Core Workflow

1. Add sanitized input through upload, case bundle, file tail, folder watch, Docker logs, an
   explicitly approved interface capture, or the opt-in loopback syslog collector.
2. Validate resource, file, and source boundaries before analysis.
3. Preserve raw lines and route them through confidence-ranked or per-line parsers.
4. Normalize supported inputs into a shared event model with parser provenance.
5. Run deterministic YAML rules and attach exact evidence IDs and MITRE context.
6. Correlate related findings into scored incidents with visible rationale.
7. Build entity and timeline views for analyst review.
8. Persist bounded investigation state in SQLite without retaining the original uploaded file.
9. Optionally request a local, evidence-bounded explanation.
10. Export Markdown, HTML, or PDF reports with optional sensitive-value redaction.

Implementation details are canonical in the
[event-processing pipeline](event-processing-pipeline.md),
[persistence lifecycle](persistence-evidence-lifecycle.md), and
[frontend architecture](frontend-architecture.md).

## Current Product Priorities

- Evidence first, AI second.
- Deterministic and reviewable detection rules.
- Findings-to-evidence traceability.
- Explainable incident correlation.
- Sanitized and reproducible demos.
- Local and Docker-first deployment.
- Explicit resource, authentication, and privacy boundaries.
- Reports that separate observed evidence from recommended analyst action.

## Current Inputs

The current parser layer covers common Linux authentication, web access, JSON, CSV, syslog,
CloudTrail, Kubernetes audit, Windows Security, Zeek, Suricata EVE, Docker, and bounded packet
metadata shapes. Coverage is deliberately smaller than an enterprise SIEM parser ecosystem.

Source-specific mappings are indexed in the [documentation hub](README.md#ingest-guides).

## Interface Capture Scope

TraceHawk can monitor an approved interface such as `wg0` through bounded `tshark` field output.
The default mode captures packet metadata: timestamp, source and destination IPs, ports, transport
protocol, frame length, and info text. It does not present payload content.

This mode is intended only for owned or explicitly authorized environments. Full PCAP retention is
a separate concern and requires written scope, authorization, and retention rules.

Initial metadata detections cover administrative-service access, DNS and packet-rate bursts, port
and host sweeps, and regular intervals that may indicate beaconing. These are investigation leads,
not final malware or compromise verdicts.

## Non-Goals

TraceHawk does not claim to be:

- a QRadar, enterprise SIEM, XDR, or production SOC replacement;
- a multi-tenant SaaS or horizontally scalable log platform;
- a complete parser, collector, endpoint-agent, or threat-intelligence ecosystem;
- an automatic blocking, remediation, or response authority;
- an AI-driven detector;
- a system authorized to capture arbitrary network traffic;
- a safe destination for production secrets, client evidence, or unsanitized public-demo data.

## Success Criteria

The current product succeeds when a reviewer can reproducibly:

1. load a bounded sanitized sample or case;
2. inspect normalized events and parser provenance;
3. trace each finding to a deterministic rule and exact evidence;
4. understand why findings were grouped and scored as an incident;
5. reopen a saved local investigation;
6. export an understandable analyst report;
7. run the documented verification gates;
8. identify the system's limitations without relying on hidden assumptions.

## Current Boundaries

Findings are heuristic and require analyst validation. The system is a single-replica,
portfolio-grade local service with SQLite persistence and bounded HTTP uploads. Detection contracts
prove declared scenarios, not population-level accuracy. Current limitations are maintained in
[limitations](limitations.md); future direction belongs in the source repository roadmap and active
plans rather than this specification.
