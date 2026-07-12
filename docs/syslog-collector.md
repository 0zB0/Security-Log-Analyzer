# Bounded Syslog Collector

TraceHawk includes an opt-in local TCP/UDP syslog receiver. It batches accepted UTF-8 lines through
the same parser, YAML detection, declarative correlation, evidence-integrity, and SQLite persistence
path as uploads. It is a bounded local collector, not a distributed ingestion service.

## Safe Defaults

The host process defaults to:

| Setting | Default | Boundary |
| --- | ---: | --- |
| Bind address | `127.0.0.1` | non-loopback binds fail unless explicitly allowed |
| UDP port | `5514` | unprivileged local syslog port |
| TCP port | `5514` | unprivileged local syslog port |
| Maximum line | `8192` bytes | oversized lines are dropped before decoding |
| Queue | `1000` lines | non-blocking overflow increments a drop counter |
| TCP connections | `32` | excess connections are closed |
| TCP idle timeout | `30` seconds | idle clients are closed |
| Batch | `100` lines | bounded persistence unit |
| Flush interval | `1` second | partial batches do not wait indefinitely |

Invalid UTF-8, empty lines, NUL-containing lines, oversized input, queue overflow, connection
rejection, timeout, failed batch analysis, and successful persistence have separate counters.
Collector JSON logs report counters, queue depth, active connections, actual ports, last analysis
ID, and last bounded error.

## Run On The Host

Install the project dependencies, then run:

```bash
PYTHONPATH=apps/api .venv/bin/python -m tracehawk_api.collector
```

The process writes completed analyses to `TRACEHAWK_DB_PATH`. It refuses `0.0.0.0`, a LAN address,
or an arbitrary hostname unless `TRACEHAWK_SYSLOG_ALLOW_REMOTE_BIND=true` is deliberately set.

## Run With Compose

Start the application and collector profiles together:

```bash
docker compose --profile production --profile collectors up --build
```

Compose publishes both protocols only on host loopback:

```text
127.0.0.1:5514 -> container 5514/udp
127.0.0.1:5514 -> container 5514/tcp
```

Inside the container the process explicitly binds `0.0.0.0` because Docker port forwarding targets
the container interface. The opt-in override is safe only in combination with the committed host
loopback publication. The default `production` and `app` profiles do not start the collector or
publish port `5514`. The Azure deployment runs only the web/API image on HTTP port `8000` and has no
collector listener.

## Send A Local Test

UDP:

```bash
printf '%s\n' 'Jul 08 09:10:00 vpn01 wg-quick[1201]: error resolving endpoint' \
  | nc -u -w1 127.0.0.1 5514
```

TCP:

```bash
printf '%s\n' 'Jul 08 09:10:20 vpn01 wg-quick[1201]: failed to update route' \
  | nc 127.0.0.1 5514
```

Five matching error lines in one five-minute window trigger `syslog-error-burst-001`. Partial
batches are still analyzed after the flush interval. Accepted syntax may route to a more specific
parser such as Linux auth when parser confidence warrants it.

## Configuration

```text
TRACEHAWK_SYSLOG_BIND_HOST=127.0.0.1
TRACEHAWK_SYSLOG_UDP_PORT=5514
TRACEHAWK_SYSLOG_TCP_PORT=5514
TRACEHAWK_SYSLOG_MAX_LINE_BYTES=8192
TRACEHAWK_SYSLOG_QUEUE_SIZE=1000
TRACEHAWK_SYSLOG_MAX_CONNECTIONS=32
TRACEHAWK_SYSLOG_IDLE_TIMEOUT_SECONDS=30
TRACEHAWK_SYSLOG_BATCH_SIZE=100
TRACEHAWK_SYSLOG_FLUSH_INTERVAL_SECONDS=1
TRACEHAWK_SYSLOG_ALLOW_REMOTE_BIND=false
TRACEHAWK_SYSLOG_STATS_INTERVAL_SECONDS=30
```

Increasing a bound changes the memory, latency, and evidence-exposure envelope. A queue overflow is
visible data loss, not retry storage. UDP has no delivery acknowledgement. TCP confirms transport
only; a later parser or persistence failure remains visible in `failed_batches` and `last_error`.

## Persistence And Integrity

Each completed batch receives a unique source filename and analysis ID. Before commit, TraceHawk
recomputes every SHA-256 hash and validates counters plus raw-event-finding-incident references.
Persisted integrity metadata records origin `syslog`. A rejected batch creates no partial analysis,
and the worker continues with later batches.

## Verification

```bash
.venv/bin/python -m pytest apps/api/tests/test_syslog_collector.py -q
make compose-check
make benchmark-smoke
```

Tests use real loopback UDP and TCP sockets, isolated SQLite persistence, malformed and oversized
input, queue saturation, remote-bind refusal, connection limits, idle timeout, failed-batch
recovery, and graceful queue drain.
