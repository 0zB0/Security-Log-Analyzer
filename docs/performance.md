# Performance And Resource Budgets

TraceHawk benchmarks run each scenario in a fresh process and record wall-clock latency, parsed
events, throughput, and Linux peak RSS. The smoke profile is a CI regression gate. The full profile
uses three repetitions and creates the committed proof report.

```bash
make benchmark-smoke
make benchmark
make benchmark-scale
```

Current scenarios cover:

- 100 KB, 1 MB, and 1.9 MB Linux auth analysis;
- 100 KB and 1 MB mixed auth/web parser routing;
- an eight-source case bundle;
- HTTP upload, SQLite persistence, and PDF report generation.

The opt-in scale profile runs direct, offline engine analysis at 10 MB, 50 MB, and 100 MB. Those
cases measure algorithmic growth outside the HTTP upload path. They do not change or bypass the
configured upload and case-bundle security limits, and they are not run on every CI change.

Robustness tests additionally cover concurrent independent analyses, very long lines, control
characters, malformed JSON lines, newline-heavy input, and recovery after a rejected upload.

The configured limits remain the security boundary. Benchmark success does not authorize files
larger than `MAX_UPLOAD_BYTES`, more files than `MAX_CASE_FILES`, or bundles larger than
`MAX_CASE_TOTAL_BYTES`.

Budgets are deliberately broad regression ceilings. They are not uptime or latency claims for
unknown production hardware, concurrent tenants, or horizontally scaled deployments.

## Observed Regression And Fix

The first 1.9 MB calibration exposed an eager threshold-window implementation that materialized
every overlapping window before the caller consumed the first match. It measured 23.35 seconds and
1,230.36 MB peak RSS. Replacing it with a streaming sliding-window iterator reduced the same
scenario to 0.51 seconds and 110.50 MB peak RSS on the reference machine. The benchmark now guards
that complexity regression in CI.
