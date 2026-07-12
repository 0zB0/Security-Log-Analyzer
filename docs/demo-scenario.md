# Demo Scenario

> Canonical for: the data and analyst story shown by the primary demo
> For click-by-click reproduction, use the [demo walkthrough](demo-walkthrough.md).

Use the active stack sample selector or upload these package samples for the primary walkthrough:

- `packages/sample-data/auth/ssh-bruteforce.log`
- `packages/sample-data/nginx/reconnaissance.log`

For the multi-source case workflow, use the `Real lab case` action in the React UI.

Expected story:

1. A source IP repeatedly fails SSH login attempts against `admin`.
2. The same source then successfully logs in.
3. The source requests sensitive web paths such as `/.env` and `/phpmyadmin`.
4. The user agent resembles scanner tooling.
5. The report correlates the findings into a single investigation thread.

Expected high-value screens:

- KPI summary with highest severity, findings, incidents, IPs, and ATT&CK count
- analyst summary
- finding list with rule IDs and confidence
- evidence viewer with exact log lines
- timeline
- Markdown/PDF report export

Expected discussion points:

- deterministic detections before AI-style narrative
- evidence-grounded summary
- false-positive notes
- MITRE mapping
- secure Azure deployment with Google login and email allowlist

The scenario defines the story, not the implementation. For the processing path see the
[event-processing pipeline](event-processing-pipeline.md); current and historical evidence is
indexed from the applicable source or community [documentation hub](README.md).
