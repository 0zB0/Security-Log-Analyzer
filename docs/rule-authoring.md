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
- `zeek-tls-suspicious-name-001`
