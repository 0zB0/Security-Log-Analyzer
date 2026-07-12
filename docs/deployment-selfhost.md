# Self-Hosted Deployment

Run the protected local demo profile on the current workstation:

```bash
docker compose --profile production up --build
```

Open:

```text
http://localhost:8000
```

The committed Compose file binds published ports to `127.0.0.1` because local mode has no external
authentication. Do not change the bind to `0.0.0.0` on a shared network. For production
self-hosting, place the app behind an identity-aware reverse proxy, enable TLS, configure explicit
authentication, and define an evidence retention policy.

## Environment Variables

```text
MAX_UPLOAD_BYTES=2000000
MAX_UPLOAD_LINES=100000
MAX_CASE_FILES=8
MAX_CASE_TOTAL_BYTES=8000000
ALLOWED_UPLOAD_EXTENSIONS=.log,.txt,.csv,.json,.jsonl,.xml
RATE_LIMIT_PER_MINUTE=120
ALLOWED_AUTH_EMAILS=
TRACEHAWK_LIVE_MAX_RAW_LINES=5000
TRACEHAWK_LIVE_MAX_EVENTS=5000
```

For a private self-hosted instance, put the app behind Cloudflare Access, Authelia, Authentik,
Traefik ForwardAuth, or another identity-aware proxy. Keep the application port loopback-bound or
reachable only from that trusted proxy.

## Optional Local Syslog Collector

```bash
docker compose --profile production --profile collectors up --build
```

The `collectors` profile publishes `5514/tcp` and `5514/udp` on `127.0.0.1` only. It is disabled
unless that profile is selected. Configuration, loss semantics, counters, and test commands are in
the [bounded syslog collector guide](syslog-collector.md).
