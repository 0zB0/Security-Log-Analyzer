# WireGuard Packet Capture Runbook

Use this workflow only on networks and companies where packet monitoring is explicitly authorized.

## Host Requirements

- Linux host with access to the WireGuard interface, for example `wg0`.
- `tshark` installed and available in `PATH`.
- Packet capture permission for the API process, usually root or `dumpcap` capabilities.

Fedora example:

```bash
sudo dnf install wireshark-cli
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"
```

## TraceHawk Live Source

Open Live Monitor and select:

- Source: `Interface Capture`
- Interface: `wg0`
- Capture filter: `ip or ip6`

Capturing on `wg0` observes decrypted inner tunnel packet metadata. Capturing on the physical
interface usually observes encrypted WireGuard UDP transport instead.

When a finding appears, use `Save` in Live Monitor to persist the current snapshot as a local
analysis run. Saved live runs can then be reviewed under Incidents and exported from Reports.

## Evidence Policy

Default TraceHawk interface monitoring stores packet metadata evidence:

- timestamp;
- source IP and port;
- destination IP and port;
- transport protocol;
- packet length;
- tshark info text;
- content hash.

Payload content is not displayed by default. Full PCAP retention must be treated as a separate
artifact with written authorization, time bounds, storage location, access control, and deletion
date.

## Proof Pack For Article Or LinkedIn

Capture these items:

- written scope and permission summary without sensitive customer details;
- interface name and capture filter;
- `tshark --version`;
- TraceHawk commit SHA;
- screenshot of Live Monitor findings;
- saved TraceHawk analysis ID from the live snapshot;
- exported Markdown/PDF report;
- content hashes from evidence lines;
- short explanation of what was detected and why it matters.

Do not publish internal IPs, hostnames, usernames, payloads, customer names, or topology unless the
permission explicitly allows publication.
