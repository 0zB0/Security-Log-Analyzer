# Detection Rules

TraceHawk rules are deterministic YAML files in `packages/rules`. Each finding includes rule ID,
severity, confidence, MITRE mapping where justified, evidence line IDs, false-positive notes, and
analyst recommendations.

## Current Rule Coverage

Auth:

- `ssh-bruteforce-001`
- `ssh-compromise-sequence-001`
- `ssh-success-after-failures-001`
- `sudo-authorized-keys-001`
- `sudo-burst-001`
- `sudo-cron-persistence-001`
- `sudo-firewall-disable-001`
- `sudo-network-download-001`
- `sudo-sensitive-file-access-001`
- `sudo-service-persistence-001`
- `sudo-user-management-001`

Web:

- `web-admin-login-probing-001`
- `web-command-injection-probing-001`
- `web-high-error-rate-001`
- `web-404-burst-001`
- `web-path-traversal-001`
- `web-scanner-user-agent-001`
- `web-sensitive-file-access-001`
- `web-source-code-extension-access-001`
- `web-sql-injection-probing-001`
- `web-webshell-upload-path-001`

JSON:

- `json-admin-login-success-001`
- `json-auth-failure-burst-001`
- `json-container-privileged-001`
- `json-encoded-command-001`
- `json-secret-file-read-001`

CSV:

- `csv-admin-login-success-001`
- `csv-auth-failure-burst-001`

CloudTrail:

- `cloudtrail-access-key-created-001`
- `cloudtrail-console-login-failure-burst-001`
- `cloudtrail-iam-policy-attachment-001`
- `cloudtrail-logging-disabled-001`
- `cloudtrail-root-account-usage-001`

Kubernetes audit:

- `kubernetes-clusterrolebinding-create-001`
- `kubernetes-forbidden-burst-001`
- `kubernetes-pod-exec-001`
- `kubernetes-privileged-pod-create-001`
- `kubernetes-secret-read-001`

Windows Security:

- `windows-account-created-001`
- `windows-admin-group-member-added-001`
- `windows-audit-log-cleared-001`
- `windows-failed-logon-burst-001`
- `windows-success-after-failures-001`

Syslog:

- `syslog-error-burst-001`

Network packet metadata:

- `network-wireguard-admin-service-access-001`
- `network-wireguard-dns-burst-001`
- `network-wireguard-host-sweep-001`
- `network-wireguard-packet-burst-001`
- `network-wireguard-periodic-beacon-001`
- `network-wireguard-port-scan-001`
- `network-wireguard-rdp-service-access-001`

Suricata EVE:

- `suricata-alert-burst-001`
- `suricata-c2-category-001`
- `suricata-dns-burst-001`
- `suricata-high-severity-alert-001`
- `suricata-http-sensitive-path-001`
- `suricata-scan-signature-001`

Zeek:

- `zeek-admin-service-access-001`
- `zeek-conn-attempt-burst-001`
- `zeek-conn-host-sweep-001`
- `zeek-conn-port-scan-001`
- `zeek-dns-burst-001`
- `zeek-http-sensitive-path-001`
- `zeek-notice-event-001`
- `zeek-stable-endpoint-retry-001`
- `zeek-tls-suspicious-name-001`

## Rule Semantics

The current rule engine supports:

- event type matching;
- threshold windows;
- distinct-count windows for port scans and host sweeps;
- periodic timing windows;
- typed two- to eight-step sequences with per-step event counts and field filters;
- exact normalized field matching;
- substring matching across normalized fields.

This keeps the MVP explainable. A finding should be reproducible from visible fields and evidence
lines without trusting a black-box classifier.
