# Current Performance Benchmark

Generated: `2026-07-10T12:17:35.277265+00:00`
Base commit: `842cfa2274e703c483fc95b26c5a767ae2cd8521`
Working tree dirty during capture: `true`
Python: `3.14.6`
Platform: `Linux-7.1.3-200.fc44.x86_64-x86_64-with-glibc2.43`

## Results

| Scenario | Payload | Lines | Events | p50 | p95 | Peak RSS | Throughput | Budget |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `offline-auth-10mb` | 10.00 MB | 105263 | 105263 | 2.5016s | 2.5016s | 422.15 MB | 42078 lines/s | PASS |
| `offline-auth-50mb` | 50.00 MB | 526315 | 526315 | 13.3395s | 13.3395s | 1970.62 MB | 39456 lines/s | PASS |
| `offline-auth-100mb` | 100.00 MB | 1052631 | 1052631 | 26.3733s | 26.3733s | 3908.14 MB | 39913 lines/s | PASS |

## Method

Each sample runs in a fresh process. Peak RSS therefore includes the Python runtime,
dependencies, application import, generated events, findings, and reports. CI uses the
smoke profile; the committed full proof uses three isolated repetitions per scenario.
Budgets are regression ceilings for this portfolio workload, not universal production SLOs.
