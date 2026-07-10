# TraceHawk Product Spec

## Product Promise

TraceHawk helps a local analyst understand suspicious log activity quickly, with deterministic findings, visible evidence, MITRE context, and private local AI explanations.

## Primary User

Junior or intermediate security analyst working in a homelab, small team, learning environment, or incident review workflow.

## Core Workflow

1. Add a log source through upload, file tail, folder watch, Docker logs, or an approved live
   network interface capture.
2. TraceHawk parses raw lines into normalized events.
3. YAML rules produce findings with severity, confidence, MITRE mapping, and evidence lines.
4. Correlation groups findings into incidents.
5. Live snapshots can be saved as persisted local analysis runs.
6. The analyst reviews timeline, evidence, entities, and recommendations.
7. Optional local LLM explains the incident from structured evidence.
8. The analyst exports a Markdown, HTML, or PDF report with optional sensitive-value redaction.

## Non-Goals

- Enterprise SIEM replacement.
- Cloud detection platform.
- Multi-tenant SaaS.
- Automatic blocking or remediation.
- Cloud LLM integration.
- Unauthorized packet capture or payload collection.

## WireGuard / Interface Capture

TraceHawk can monitor a WireGuard interface such as `wg0` through `tshark` field output. The
default mode captures packet metadata only: timestamp, source and destination IPs, ports,
transport protocol, frame length, and tshark info text. It does not display payload content.

This mode is intended for owned or explicitly authorized environments where the analyst can prove
scope, consent, timestamps, tool version, and capture filters. Full PCAP retention should be a
separate, bounded artifact with written authorization and retention rules.

Initial live network detections cover high-signal metadata patterns:

- administrative service access such as SSH or RDP over the monitored interface;
- DNS and packet-rate bursts;
- one source touching many destination ports on one host;
- one source touching one service across many hosts;
- regular interval traffic that may indicate beaconing.

Packet-level beaconing is an early indicator, not a final malware verdict. Analyst confirmation
should combine it with host process evidence, resolver/proxy logs, Zeek flow logs, or Suricata
alerts where available.
