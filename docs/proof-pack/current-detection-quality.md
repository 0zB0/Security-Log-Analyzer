# Current Detection Quality

Generated: `2026-07-12T21:02:18.750749+00:00`

## Contract Summary

| Measure | Result |
| --- | ---: |
| Detection rules | 66 |
| Rules with a positive contract | 66 |
| Labeled scenarios | 35 |
| Benign negative-control scenarios | 12 |
| True-positive rule matches | 73 |
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
- `zeek-stable-endpoint-retry-benign`

All committed negative controls produced zero findings. Exact-port controls include
Zeek destination port `33022`, which must not match SSH port `22`.
