# Rule Authoring

Detection rules are YAML files stored under `packages/rules`.

## Rule Requirements

Each production rule should include:

- stable `id`;
- clear `title`;
- analyst-focused `description`;
- `severity`;
- `confidence`;
- supported `log_types`;
- MITRE mapping where justified;
- explicit correlation metadata when the rule participates in incident patterns;
- deterministic `conditions`;
- evidence policy;
- false-positive notes;
- recommendations.

## Example

```yaml
id: ssh-bruteforce-001
title: SSH brute force attempt
description: Multiple failed SSH login attempts from one source IP.
severity: high
confidence: high
log_types:
  - linux_auth
mitre:
  tactic: Credential Access
  technique_id: T1110.001
  technique_name: Password Guessing
correlation:
  family: credential_access
  behaviors:
    - ssh_failures
  entity_fields:
    - source_ip
    - username
  max_gap_minutes: 15
conditions:
  event_type: ssh_failed_login
  group_by:
    - source_ip
    - username
  window_minutes: 10
  count_gte: 10
evidence:
  include_matching_lines: true
  max_lines: 20
false_positives:
  - Misconfigured service repeatedly using an old password.
  - Internal vulnerability scanner.
recommendations:
  - Review whether any successful login followed the failed attempts.
  - Block the source IP if confirmed malicious.
  - Disable password authentication where possible.
```

## Supported Conditions

Current rule engine support is intentionally deterministic and small:

- `event_type`: match a parsed event type.
- `group_by`: group matching events by event attributes such as `source_ip` or `username`.
- `window_minutes` plus `count_gte`: threshold detections in a sliding time window.
- `distinct_field` plus `distinct_count_gte`: cardinality detections such as many
  destination ports or hosts in one window.
- `periodic_count_gte` with `periodic_interval_seconds_min`,
  `periodic_interval_seconds_max`, and `periodic_jitter_seconds_lte`: regular
  interval detections such as beaconing.
- `sequence`: two to eight ordered steps. Each step requires `event_type` and may add
  `count_gte`, `field_equals`, `field_in`, or `field_contains_any`.
- `path_contains_any`: shortcut for matching substrings in `url_path`.
- `field_equals`: exact match against an event attribute or normalized field.
- `field_in`: exact match against one of several values.
- `field_contains_any`: substring match against an event attribute or normalized field.

Fields first check the parsed event model, then `normalized_fields`. For example, `source_ip`
matches the top-level event field, while `command`, `url_path`, `url_target`, `status_code`, and
`user_agent` come from parser-specific normalized fields.

Sequence rules use one global `window_minutes` value and never reuse one event for multiple steps:

```yaml
conditions:
  sequence:
    - event_type: ssh_failed_login
      count_gte: 10
    - event_type: ssh_successful_login
    - event_type: sudo_command
      field_contains_any:
        command:
          - useradd
          - authorized_keys
  group_by:
    - username
  window_minutes: 30
```

Rules with fewer than two or more than eight steps, unknown step keys, missing event types, or
invalid counts fail validation when the rule library loads. They are never silently skipped.

## Correlation Metadata

Correlation metadata is behavior-oriented and independent of a rule's ID or title:

- `family`: lowercase semantic family used for diversity scoring;
- `incident_title`: optional shared title for an unmatched multi-finding incident;
- `behaviors`: unique lowercase tags consumed by `packages/correlation/patterns.yml`;
- `entity_fields`: one or more stable grouping keys from `source_ip`, `destination_ip`, `username`,
  and `host`;
- `max_gap_minutes`: strict maximum total span for an incident containing this rule;
- `intrinsic_sequence_score`: optional `0..25` score for an ordered sequence already proven by the
  rule itself;
- `intrinsic_sequence_rationale`: required when the intrinsic score is positive;
- `intrinsic_sequence_summary`: optional analyst-facing sentence.

Use a behavior for what the evidence means, not where the YAML file lives. For example,
`network_scan` can be emitted by Zeek, Suricata, or packet-metadata rules. Do not encode behavior in
an ID with the expectation that Python will inspect the name.

Choose entity fields narrowly. A credential rule normally uses source IP and username. A network
flow rule normally uses source and destination IP. Host is a fallback when no enabled stronger
entity exists; it should not be used to collapse unrelated users or remote endpoints on one host.

Multi-rule behavior belongs in the versioned pattern library, not in Python conditionals. Every
pattern tag must be declared by at least one rule or readiness fails.

For JSON logs, nested fields are flattened with dot notation. Example:

```json
{"event":{"action":"process_start"},"process":{"command_line":"bash -c ..."}}
```

This can be matched as:

```yaml
conditions:
  field_contains_any:
    process.command_line:
      - base64
```

## Current Rule Set

Auth rules:

- `sudo-authorized-keys-001`
- `ssh-bruteforce-001`
- `ssh-compromise-sequence-001`
- `ssh-success-after-failures-001`
- `sudo-burst-001`
- `sudo-cron-persistence-001`
- `sudo-firewall-disable-001`
- `sudo-network-download-001`
- `sudo-sensitive-file-access-001`
- `sudo-service-persistence-001`
- `sudo-user-management-001`

Web rules:

- `web-command-injection-probing-001`
- `web-404-burst-001`
- `web-high-error-rate-001`
- `web-admin-login-probing-001`
- `web-path-traversal-001`
- `web-scanner-user-agent-001`
- `web-sensitive-file-access-001`
- `web-source-code-extension-access-001`
- `web-sql-injection-probing-001`
- `web-webshell-upload-path-001`

JSON rules:

- `json-admin-login-success-001`
- `json-auth-failure-burst-001`
- `json-container-privileged-001`
- `json-encoded-command-001`
- `json-secret-file-read-001`

CSV rules:

- `csv-admin-login-success-001`
- `csv-auth-failure-burst-001`

CloudTrail rules:

- `cloudtrail-access-key-created-001`
- `cloudtrail-console-login-failure-burst-001`
- `cloudtrail-iam-policy-attachment-001`
- `cloudtrail-logging-disabled-001`
- `cloudtrail-root-account-usage-001`

Kubernetes audit rules:

- `kubernetes-clusterrolebinding-create-001`
- `kubernetes-forbidden-burst-001`
- `kubernetes-pod-exec-001`
- `kubernetes-privileged-pod-create-001`
- `kubernetes-secret-read-001`

Windows Security rules:

- `windows-account-created-001`
- `windows-admin-group-member-added-001`
- `windows-audit-log-cleared-001`
- `windows-failed-logon-burst-001`
- `windows-success-after-failures-001`

Syslog rules:

- `syslog-error-burst-001`

Network packet rules:

- `network-wireguard-admin-service-access-001`
- `network-wireguard-dns-burst-001`
- `network-wireguard-host-sweep-001`
- `network-wireguard-packet-burst-001`
- `network-wireguard-periodic-beacon-001`
- `network-wireguard-port-scan-001`
- `network-wireguard-rdp-service-access-001`

Suricata EVE rules:

- `suricata-alert-burst-001`
- `suricata-c2-category-001`
- `suricata-dns-burst-001`
- `suricata-high-severity-alert-001`
- `suricata-http-sensitive-path-001`
- `suricata-scan-signature-001`

Zeek rules:

- `zeek-admin-service-access-001`
- `zeek-conn-attempt-burst-001`
- `zeek-conn-host-sweep-001`
- `zeek-conn-port-scan-001`
- `zeek-dns-burst-001`
- `zeek-http-sensitive-path-001`
- `zeek-notice-event-001`
- `zeek-stable-endpoint-retry-001`
- `zeek-tls-suspicious-name-001`
