# Current IoT-23 Detection Evaluation

Generated: `2026-07-09T21:39:21.333994+00:00`

## Dataset And Scope

Stratosphere Laboratory. A labeled dataset with malicious and benign IoT network traffic. Agustin Parmisano, Sebastian Garcia, Maria Jose Erquiaga.

Evaluate deterministic Zeek connection-attempt, host-sweep, and port-scan findings against the IoT-23 PartOfAHorizontalPortScan label.

| Capture | Parsed rows | SHA-256 |
| --- | ---: | --- |
| [iot23-34-1-conn.log.labeled](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled) | 23145 | `d69e49b2aae8c1bd33286936531658202dec47d989f0439bad3f8be180467a6e` |
| [iot23-benign-4-1-conn.log.labeled](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled) | 452 | `aebe40ea0e03b120265a5c7bc140dd9b0d3fe2fce65559e84776b7dd5360e71e` |

## Scan Window Metrics

| Measure | Result |
| --- | ---: |
| Two-minute windows | 880 |
| True-positive windows | 1 |
| False-positive windows | 1 |
| False-negative windows | 1 |
| True-negative windows | 877 |
| Precision | 0.5000 |
| Recall | 0.5000 |
| False-positive rate | 0.0011 |

## Limitations

- Fixed windows can split activity across a boundary.
- Only scan rules are scored; C&C and DDoS labels are outside this evaluation.
- IoT-23 is a controlled research dataset and is not current production traffic.
- Metrics are window-level, not packet-level or host-level prevalence estimates.

## Error Analysis

The observed false-positive window is labeled as DDoS rather than horizontal scan,
but it contains the same repeated unsuccessful connection-attempt shape detected by
`zeek-conn-attempt-burst-001`. Under this narrow label objective it is
counted as a false positive; operationally it remains suspicious behavior requiring
classification rather than suppression.

- Window: `2018-12-22T10:50:00+00:00`
- Events: 151
- Labels: `{"C&C": 18, "DDoS": 133}`

The false-negative window contains an isolated scan-labeled flow below the 100-event
burst threshold. Lowering the threshold solely to capture this point would weaken the
benign and DDoS separation and is not justified by this dataset alone.

- Window: `2018-12-22T05:22:00+00:00`
- Events: 5
- Labels: `{"Benign": 4, "PartOfAHorizontalPortScan": 1}`
