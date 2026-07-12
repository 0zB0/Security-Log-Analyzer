# Case Study: Making IoT-23 Uncertainty Visible

## Problem

The original IoT-23 proof accurately reported precision and recall of `0.5`, but each point estimate
was based on one true positive, one false positive, and one false negative. A reviewer could mistake
the decimal values for stable population-level detection quality.

## Reproduction

The two checked captures produce 880 fixed two-minute windows:

```text
TP=1, FP=1, FN=1, TN=877
```

The false-positive window is DDoS/C&C-labeled but operationally suspicious, while the false-negative
window contains one scan-labeled flow among five events. Neither error supports broad rule tuning on
its own.

## Decision

Preserve raw counts and add metrics that expose class imbalance and sample uncertainty:

- F1, specificity, balanced accuracy, and positive prevalence;
- Wilson 95% intervals for precision, recall, and specificity;
- per-capture confusion counts;
- per-rule detected-window counts;
- a manifest separating tuning fixtures from final external evaluation inputs.

Wilson intervals were selected over a normal approximation because the positive denominators are
extremely small. The tool also accepts repeated capture arguments so future datasets do not require
rewriting evaluation logic.

## Verification

```bash
.venv/bin/python -m pytest apps/api/tests/test_evaluation_metrics.py -q
.venv/bin/python tools/evaluate_iot23.py \
  --input /path/to/iot23-34-1-conn.log.labeled \
  --benign-input /path/to/iot23-benign-4-1-conn.log.labeled
```

The raw matrix must remain `1/1/1/877`. Precision and recall remain `0.5`, while both 95% intervals
are approximately `0.0945–0.9055`, making the uncertainty explicit.

## Residual Risk

The scan result remains exactly `TP=1, FP=1, FN=1, TN=877`; adding data must not rewrite historical
error interpretation.

The later v0.9.0 extension added a second objective for a neutral, low-confidence stable-endpoint
retry rule. Capture roles were frozen before final scoring: `20-1` development, `21-1` and `8-1`
validation, `42-1` and `44-1` final, and benign `4-1` negative control. The final matrix was:

```text
TP=2, FP=21, FN=1, TN=246
precision=0.0870, recall=0.6667, specificity=0.9213
```

Most false-positive windows come from repeated endpoint retries labeled benign in capture `42-1`.
That result was retained without threshold retuning. It shows that the shape can be a hunting lead
but is not a specific C2 classifier. External evidence now covers two behavior families, but it
still does not validate all 66 rules, current enterprise traffic, or production prevalence.
