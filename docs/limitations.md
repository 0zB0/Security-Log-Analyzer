# Limitations

- Detection rules are heuristic and can produce false positives.
- The analyzer does not prove compromise without identity, endpoint, and network corroboration.
- Timestamp parsing is conservative and does not normalize every vendor format.
- The app does not persist uploaded files. It does persist local analysis records and evidence
  line text in SQLite for report/export workflows.
- Built-in summaries are grounded and deterministic; no external LLM is called by default.
- The in-memory rate limiter is suitable for a demo, not a horizontally scaled production deployment.
- Live file, folder, Docker, and interface analysis retains only the configured rolling evidence
  and event windows. Drop counters disclose eviction, but evicted telemetry cannot be reconstructed
  from a saved snapshot.
- The opt-in syslog collector is loopback-default and uses an in-memory queue plus local SQLite. UDP
  can lose packets; queue overflow drops lines; there is no durable broker, sender acknowledgement,
  replay protocol, collector fleet, or Azure listener.
- File parsing currently covers common auth, web, JSON, CSV, syslog, Zeek, Suricata EVE, and
  bounded packet metadata. It is not a full SIEM parser library.
- The frozen IoT-23 stable-endpoint C2-indicator slice has `0.0870` precision. It is a
  low-confidence hunting shape, not a production C2 classifier or evidence that all 66 rules have
  external accuracy validation.
- Generated TypeScript contracts detect backend/frontend schema drift at build time but do not
  runtime-validate responses from a compromised or mismatched backend.
- Automated frontend proof covers Chromium critical paths and selected axe states, not every
  browser, viewport, screen reader, or secondary error branch.
- Mixed line-oriented text dumps are routed per line. Stateful CSV and Zeek TSV sections require
  their header metadata before their data rows; arbitrarily interleaved headerless rows are skipped.
- Optional trusted-proxy authentication, fail-closed email allowlisting, viewer/analyst/admin RBAC,
  and a SQLite audit trail protect a single application instance. This is not tenant isolation or
  an enterprise identity lifecycle system, and horizontally scaled deployments need a centralized
  immutable audit sink.
