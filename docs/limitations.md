# Limitations

- Detection rules are heuristic and can produce false positives.
- The analyzer does not prove compromise without identity, endpoint, and network corroboration.
- Timestamp parsing is conservative and does not normalize every vendor format.
- The app does not persist uploaded files. It does persist local analysis records and evidence
  line text in SQLite for report/export workflows.
- Built-in summaries are grounded and deterministic; no external LLM is called by default.
- The in-memory rate limiter is suitable for a demo, not a horizontally scaled production deployment.
- File parsing currently covers common auth, web, JSON, CSV, syslog, Zeek, Suricata EVE, and
  bounded packet metadata. It is not a full SIEM parser library.
- Mixed line-oriented text dumps are routed per line. Stateful CSV and Zeek TSV sections require
  their header metadata before their data rows; arbitrarily interleaved headerless rows are skipped.
- Optional trusted-proxy authentication, fail-closed email allowlisting, viewer/analyst/admin RBAC,
  and a SQLite audit trail protect a single application instance. This is not tenant isolation or
  an enterprise identity lifecycle system, and horizontally scaled deployments need a centralized
  immutable audit sink.
