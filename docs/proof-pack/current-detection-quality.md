# Current Detection Quality

Generated: `2026-07-09T21:39:53.740722+00:00`

## Contract Summary

| Measure | Result |
| --- | ---: |
| Detection rules | 65 |
| Rules with a positive contract | 65 |
| Labeled scenarios | 33 |
| Benign negative-control scenarios | 11 |
| True-positive rule matches | 71 |
| Unexpected rule matches | 0 |
| Missing expected matches | 0 |
| Contract precision | 1.0000 |
| Contract recall | 1.0000 |

## Interpretation

Contract metrics prove committed labeled scenarios, not population-level production accuracy. External IoT-23 results are reported separately.
The external IoT-23 evaluation is maintained as a separate proof because a committed
contract suite cannot establish real-world prevalence or population-level false-positive rates.

## Negative Controls

- `benign-no-alert`
- `cloudtrail-benign`
- `csv-benign`
- `json-benign`
- `kubernetes-benign`
- `suricata-benign-no-alert`
- `syslog-benign`
- `web-benign`
- `windows-benign`
- `zeek-admin-service-benign`
- `zeek-benign-no-alert`

All committed negative controls produced zero findings. Exact-port controls include
Zeek destination port `33022`, which must not match SSH port `22`.
