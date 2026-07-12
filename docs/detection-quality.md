# Detection Quality Method

TraceHawk separates three evidence layers:

1. Unit and parser tests prove field normalization and rule semantics.
2. Committed labeled scenarios prove deterministic rule contracts and benign negative controls.
3. IoT-23 evaluation measures selected Zeek scan and stable-endpoint retry behavior against an
   external labeled dataset with development, validation, final, and negative-control roles.

The contract report is generated with:

```bash
make detection-quality
```

The external report requires the CC-BY IoT-23 `conn.log.labeled` files and never downloads or
commits malware binaries:

```bash
.venv/bin/python tools/evaluate_iot23.py \
  --input /path/to/CTU-IoT-Malware-Capture-34-1/conn.log.labeled \
  --input /path/to/CTU-IoT-Malware-Capture-20-1/conn.log.labeled \
  --input /path/to/CTU-IoT-Malware-Capture-21-1/conn.log.labeled \
  --input /path/to/CTU-IoT-Malware-Capture-8-1/conn.log.labeled \
  --input /path/to/CTU-IoT-Malware-Capture-42-1/conn.log.labeled \
  --input /path/to/CTU-IoT-Malware-Capture-44-1/conn.log.labeled \
  --benign-input /path/to/CTU-Honeypot-Capture-4-1/conn.log.labeled
```

Contract precision and recall are not population-level accuracy claims. They answer whether the
current rule library produces exactly the declared matches on committed labeled inputs. IoT-23
metrics are reported separately because their labels, traffic prevalence, capture age, fixed window
boundaries, and supported TraceHawk rule families differ from the contract suite.

The evaluator supports both IoT-23 TSV layouts: separate `label`/`detailed-label` columns and the
legacy combined final column. It retains TP/FP/FN/TN, F1, specificity, balanced accuracy, positive
prevalence, Wilson 95% intervals, per-capture results, and concrete error windows for each behavior
family.

Dataset roles are frozen in `docs/evaluation-manifest.json`. Development capture `20-1` may guide
the stable-endpoint rule. Captures `21-1` and `8-1` are validation because their outcomes were
inspected before finalization. Captures `42-1` and `44-1` are final holdouts and may be scored only
after the six-attempt, five-minute threshold is committed. The benign `4-1` capture contributes
negative windows to both final objectives. Development and validation metrics remain visible but
are never pooled into final metrics.

Rule tuning must record:

- the observed false positive or false negative;
- the exact fixture or external window;
- the rule change and rationale;
- a negative regression case;
- results before and after the change.

The scan proof intentionally retains one DDoS-labeled window detected as a repeated
connection-attempt burst and one isolated scan-labeled window below threshold. These are documented
error cases, not hidden by aggregate scoring or dataset-specific threshold tuning.

The stable-endpoint rule is explicitly low confidence. It measures a repeated failed TCP retry
shape against the C&C label family; it does not claim that failed connections prove command and
control, and it is expected to miss C&C activity without that shape.

## Current External Results

| Objective | Final captures | TP | FP | FN | TN | Precision | Recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Network scan | `34-1` plus benign `4-1` | 1 | 1 | 1 | 877 | 0.5000 | 0.5000 |
| Stable-endpoint C2 indicator | `42-1`, `44-1` plus benign `4-1` | 2 | 21 | 1 | 246 | 0.0870 | 0.6667 |

The C2-indicator result is not a success disguised by recall. Twenty-one benign-labeled windows in
capture `42-1` contain the same repeated unavailable-endpoint shape, so the final precision is only
`0.0870` with a Wilson interval of `0.0242–0.2680`. TraceHawk retains the neutral behavior title,
medium severity, low confidence, per-capture errors, and unchanged frozen threshold. It must not be
described as a specific C2 classifier.
