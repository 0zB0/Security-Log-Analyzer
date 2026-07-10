# Self-Hosted Deployment

Run locally or on a Docker host:

```bash
docker compose up --build
```

Open:

```text
http://localhost:8000
```

For production self-hosting, place the app behind a reverse proxy, enable TLS, add authentication, and store uploads outside the container with a retention policy.

## Environment Variables

```text
MAX_UPLOAD_BYTES=2000000
MAX_UPLOAD_LINES=100000
MAX_CASE_FILES=8
MAX_CASE_TOTAL_BYTES=8000000
ALLOWED_UPLOAD_EXTENSIONS=.log,.txt,.csv,.json,.jsonl,.xml
RATE_LIMIT_PER_MINUTE=120
ALLOWED_AUTH_EMAILS=
```

For a private self-hosted instance, put the app behind Cloudflare Access, Authelia, Authentik, Traefik ForwardAuth, or another identity-aware proxy.
