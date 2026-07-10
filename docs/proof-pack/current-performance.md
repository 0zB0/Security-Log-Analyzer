# Current Performance Benchmark

Generated: `2026-07-09T21:55:57.681229+00:00`

Base commit: `6dc6cfdfaaa46e8d1fd8c4aeb95386ef6b3054a0`

Working tree dirty during capture: `true`

Python: `3.14.6`

Platform: `Linux-7.1.3-200.fc44.x86_64-x86_64-with-glibc2.43`

## Results

| Scenario | Payload | Lines | Events | p50 | p95 | Peak RSS | Throughput | Budget |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `core-auth-100kb` | 0.10 MB | 1063 | 1063 | 0.1313s | 0.1342s | 38.48 MB | 8096 lines/s | PASS |
| `core-auth-1mb` | 1.00 MB | 10629 | 10629 | 0.3142s | 0.3147s | 74.55 MB | 33832 lines/s | PASS |
| `core-auth-near-limit` | 1.90 MB | 20195 | 20195 | 0.5040s | 0.5216s | 110.44 MB | 40069 lines/s | PASS |
| `core-mixed-100kb` | 0.10 MB | 1054 | 1054 | 0.1345s | 0.1360s | 38.49 MB | 7837 lines/s | PASS |
| `core-mixed-1mb` | 1.00 MB | 10547 | 10547 | 0.3810s | 0.3854s | 74.31 MB | 27681 lines/s | PASS |
| `case-bundle-eight-sources` | 7.20 MB | 76528 | 76528 | 2.4303s | 2.4829s | 320.33 MB | 31489 lines/s | PASS |
| `api-upload-pdf-report` | 0.00 MB | 13 | 12 | 0.4451s | 0.4529s | 90.77 MB | 29 lines/s | PASS |

## Method

Each sample runs in a fresh process. Peak RSS therefore includes the Python runtime,
dependencies, application import, generated events, findings, and reports. CI uses the
smoke profile; the committed full proof uses three isolated repetitions per scenario.
Budgets are regression ceilings for this portfolio workload, not universal production SLOs.
