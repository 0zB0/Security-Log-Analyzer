# Detection Quality Method

TraceHawk separates three evidence layers:

1. Unit and parser tests prove field normalization and rule semantics.
2. Committed labeled scenarios prove deterministic rule contracts and benign negative controls.
3. IoT-23 evaluation measures selected Zeek scan rules against an external labeled dataset.

The contract report is generated with:

```bash
make detection-quality
```

The external report requires the CC-BY IoT-23 `conn.log.labeled` files and never downloads or
commits malware binaries:

```bash
.venv/bin/python tools/evaluate_iot23.py \
  --input /path/to/CTU-IoT-Malware-Capture-34-1/conn.log.labeled \
  --benign-input /path/to/CTU-Honeypot-Capture-4-1/conn.log.labeled
```

Contract precision and recall are not population-level accuracy claims. They answer whether the
current rule library produces exactly the declared matches on committed labeled inputs. IoT-23
metrics are reported separately because their labels, traffic prevalence, capture age, fixed window
boundaries, and supported TraceHawk rule families differ from the contract suite.

The external report retains TP/FP/FN/TN counts and also shows F1, specificity, balanced accuracy,
positive prevalence, per-capture results, per-rule detected windows, and Wilson 95% intervals. With
only two ground-truth-positive and two predicted-positive windows, the precision and recall point
estimates have wide intervals and must not be generalized to the complete rule library. Dataset
roles and required metadata are recorded in `docs/evaluation-manifest.json` so tuning inputs are not
silently presented as final evaluation evidence.

Rule tuning must record:

- the observed false positive or false negative;
- the exact fixture or external window;
- the rule change and rationale;
- a negative regression case;
- results before and after the change.

The current IoT-23 proof intentionally retains one DDoS-labeled window detected as a repeated
connection-attempt burst and one isolated scan-labeled window below threshold. These are documented
error cases, not hidden by aggregate scoring or dataset-specific threshold tuning.
