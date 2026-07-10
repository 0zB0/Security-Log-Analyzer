# Incident Correlation

TraceHawk groups deterministic findings into incidents so analysts review security stories instead of isolated alerts.

## Current Strategy

The current correlation engine builds a small entity graph from finding evidence. Each finding
contributes correlation entities from its evidence events:

- source IP;
- username;
- host.

Source IP and username are primary correlation entities. Host is only used as a fallback when no
IP or username is present, so unrelated activity on the same machine is less likely to collapse
into one incident.

Findings become part of the same incident when their correlation entity sets overlap. This lets
TraceHawk join related evidence such as:

- SSH brute force from `185.34.22.10` against `admin`;
- successful SSH login by `admin`;
- subsequent sudo command by `admin` without a source IP in the sudo log line.

## Incident Fields

Each incident includes:

- title;
- severity;
- score;
- score breakdown by deterministic component;
- score rationale explaining sequence, time-window, cross-source, and
  rule-family contributions;
- linked finding IDs;
- related entities;
- MITRE techniques;
- timeline generated from evidence events.

## Current Scoring Components

Incident score is deterministic and capped at 100. The score breakdown exposes
the contribution from:

- base severity;
- finding volume;
- sequence quality;
- time-window proximity;
- cross-source corroboration;
- rule-family diversity.

The first sequence patterns are:

- scan followed by sensitive HTTP path access;
- DNS burst followed by related alert or C2 activity;
- alert burst with high severity Suricata evidence;
- SSH failures followed by successful login and sudo activity.
- a typed three-step SSH failure, successful login, and privileged persistence chain.

Guardrail tests also verify that:

- DNS burst without alert or C2 follow-up does not receive sequence points;
- scan activity without sensitive HTTP follow-up does not receive sequence
  points;
- unrelated cross-source links do not increase an incident score;
- findings outside the scoring time window do not receive time-window proximity
  or ordered sequence points.

## Case Quality Summary

Case bundle analysis exposes a `case_quality` summary with:

- strongest incident ID, title, and score;
- count of sequence-backed incidents;
- count of cross-source-corroborated incidents;
- total cross-source link count;
- top scoring reason from the strongest incident.

## Current Incident Titles

Known rule combinations produce analyst-friendly titles:

- `ssh-success-after-failures-001` -> `Possible SSH credential compromise`;
- `ssh-bruteforce-001` -> `SSH brute force activity`;
- `sudo-*` -> `Privileged sudo activity`;
- `web-sensitive-file-access-001` -> `Web probing against sensitive files`.

## Why This Matters

An alert table is not enough for a SOC workflow. Incident correlation helps show:

- what happened;
- which findings belong together;
- which entities are involved;
- what timeline should be reviewed first.

Future correlation improvements should add entity risk memory, analyst status,
and local LLM summaries.
