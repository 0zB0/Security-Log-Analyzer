# Current IoT-23 Detection Evaluation

Generated: `2026-07-12T21:04:06.529562+00:00`

## Dataset And Role Separation

Stratosphere Laboratory. A labeled dataset with malicious and benign IoT network traffic. Agustin Parmisano, Sebastian Garcia, Maria Jose Erquiaga.

Development and validation captures are reported but excluded from final metrics. Final
metrics combine only frozen holdout captures and the assigned benign negative control.
C2-indicator rule freeze commit: `df5811a6f98e48ea046247fcbb770fa9ecbd32ed`.

| Capture | Role | Objectives | Rows | Label format | SHA-256 |
| --- | --- | --- | ---: | --- | --- |
| [34-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled) | final_evaluation | network_scan | 23145 | separate_columns | `d69e49b2aae8c1bd33286936531658202dec47d989f0439bad3f8be180467a6e` |
| [20-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-20-1/bro/conn.log.labeled) | development | command_and_control | 3209 | combined_column | `ef48ad72f65efd13d517223e61e4d877ba53a082ddb8159324b18d3f310d0711` |
| [21-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-21-1/bro/conn.log.labeled) | validation | command_and_control | 3286 | combined_column | `b63db259aead078f50fc150aa97ace4d1f69576e1245334962759d978ce437eb` |
| [8-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-8-1/bro/conn.log.labeled) | validation | command_and_control | 10403 | combined_column | `4877ca8f0f01902fbd18d28b7d06cb3d0be082355b7f2c8862c9deef1782eb8a` |
| [42-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-42-1/bro/conn.log.labeled) | final_evaluation | command_and_control | 4426 | combined_column | `269fa1b22d9a37e159cf41b81a213a0032d21306f5d39b4c20cb0d211b04e8aa` |
| [44-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-44-1/bro/conn.log.labeled) | final_evaluation | command_and_control | 237 | combined_column | `12cd99bcda78140dd5f31cf3d786642f150e42e0ebc3599190f35314e406f71f` |
| [4-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled) | negative_control | network_scan, command_and_control | 452 | combined_column | `aebe40ea0e03b120265a5c7bc140dd9b0d3fe2fce65559e84776b7dd5360e71e` |

## Horizontal network-scan windows

Objective ID: `network_scan`

- Window: 120 seconds
- Rules: `zeek-conn-attempt-burst-001, zeek-conn-host-sweep-001, zeek-conn-port-scan-001`
- Ground truth: A window contains at least one `PartOfAHorizontalPortScan` flow.
- Prediction: A window produces a Zeek connection-attempt burst, host-sweep, or port-scan finding.
- Frozen final captures: `34-1`
- Negative controls: `4-1`

### Final Metrics

| Measure | Result |
| --- | ---: |
| Windows | 880 |
| TP | 1 |
| FP | 1 |
| FN | 1 |
| TN | 877 |
| Precision | 0.5000 |
| Precision 95% Wilson interval | 0.0945–0.9055 |
| Recall | 0.5000 |
| Recall 95% Wilson interval | 0.0945–0.9055 |
| F1 | 0.5000 |
| Specificity | 0.9989 |
| Balanced accuracy | 0.7494 |
| Positive prevalence | 0.0023 |

### Per-Capture Results

| Capture | Role | Windows | TP | FP | FN | TN | Detected rules |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 34-1 | final_evaluation | 699 | 1 | 1 | 1 | 696 | zeek-conn-attempt-burst-001: 2 |
| 4-1 | negative_control | 181 | 0 | 0 | 0 | 181 | none |

### Final Error Analysis

- `FP` capture `34-1`, window `2018-12-22T10:50:00+00:00`: 151 events, labels `{"C&C": 18, "DDoS": 133}`, rules `zeek-conn-attempt-burst-001`.
- `FN` capture `34-1`, window `2018-12-22T05:22:00+00:00`: 5 events, labels `{"Benign": 4, "PartOfAHorizontalPortScan": 1}`, rules `none`.

## Stable-endpoint C2-indicator windows

Objective ID: `command_and_control`

- Window: 300 seconds
- Rules: `zeek-stable-endpoint-retry-001`
- Ground truth: A window contains at least one label in the C&C or a detailed label beginning with C&C- family.
- Prediction: A window produces the low-confidence repeated failed stable-endpoint finding.
- Frozen final captures: `42-1, 44-1`
- Negative controls: `4-1`

### Final Metrics

| Measure | Result |
| --- | ---: |
| Windows | 270 |
| TP | 2 |
| FP | 21 |
| FN | 1 |
| TN | 246 |
| Precision | 0.0870 |
| Precision 95% Wilson interval | 0.0242–0.2680 |
| Recall | 0.6667 |
| Recall 95% Wilson interval | 0.2077–0.9385 |
| F1 | 0.1538 |
| Specificity | 0.9213 |
| Balanced accuracy | 0.7940 |
| Positive prevalence | 0.0111 |

### Per-Capture Results

| Capture | Role | Windows | TP | FP | FN | TN | Detected rules |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 20-1 | development | 289 | 1 | 0 | 2 | 286 | zeek-stable-endpoint-retry-001: 1 |
| 21-1 | validation | 265 | 1 | 0 | 2 | 262 | zeek-stable-endpoint-retry-001: 1 |
| 8-1 | validation | 289 | 274 | 0 | 2 | 13 | zeek-stable-endpoint-retry-001: 274 |
| 42-1 | final_evaluation | 99 | 1 | 21 | 1 | 76 | zeek-stable-endpoint-retry-001: 22 |
| 44-1 | final_evaluation | 24 | 1 | 0 | 0 | 23 | zeek-stable-endpoint-retry-001: 1 |
| 4-1 | negative_control | 147 | 0 | 0 | 0 | 147 | none |

### Final Error Analysis

- `FP` capture `42-1`, window `2019-01-10T13:40:00+00:00`: 187 events, labels `{"Benign": 187}`, rules `zeek-stable-endpoint-retry-001`.
- `FP` capture `42-1`, window `2019-01-10T13:45:00+00:00`: 193 events, labels `{"Benign": 193}`, rules `zeek-stable-endpoint-retry-001`.
- `FP` capture `42-1`, window `2019-01-10T13:50:00+00:00`: 139 events, labels `{"Benign": 139}`, rules `zeek-stable-endpoint-retry-001`.
- `FP` capture `42-1`, window `2019-01-10T13:55:00+00:00`: 149 events, labels `{"Benign": 149}`, rules `zeek-stable-endpoint-retry-001`.
- `FP` capture `42-1`, window `2019-01-10T14:00:00+00:00`: 167 events, labels `{"Benign": 167}`, rules `zeek-stable-endpoint-retry-001`.
- `FN` capture `42-1`, window `2019-01-10T13:30:00+00:00`: 9 events, labels `{"Benign": 6, "C&C-FileDownload": 2, "FileDownload": 1}`, rules `none`.

## Limitations

- Fixed windows can split activity across a boundary.
- The C2 objective measures one low-confidence retry indicator, not all C2 behavior.
- IoT-23 is a controlled, historical research dataset, not current production traffic.
- Metrics are window-level and do not estimate packet-, flow-, host-, or tenant prevalence.
- Capture heterogeneity makes per-capture errors more informative than one pooled score.
