# Demo Walkthrough

## Target Scenario

The demo should show a realistic small incident:

1. An external IP probes a web server.
2. The same IP requests sensitive files such as `.env`.
3. SSH brute force attempts begin against `admin`.
4. One login succeeds after repeated failures.
5. Sudo activity follows.
6. TraceHawk correlates the activity into an incident.
7. Local LLM explains the incident.
8. A report is exported.

## Local Sample Flow

Start the API and web app in two terminals:

```bash
make api-dev
npm --prefix apps/web run dev
```

Then upload the built-in samples from the UI or with curl:

```bash
curl -F "file=@packages/sample-data/nginx/reconnaissance.log" \
  http://localhost:8000/api/analyze/upload

curl -F "file=@packages/sample-data/auth/ssh-bruteforce.log" \
  http://localhost:8000/api/analyze/upload

curl -F "file=@packages/sample-data/json/security-events.jsonl" \
  http://localhost:8000/api/analyze/upload
```

For live mode, point the UI at one file, or connect directly:

```text
ws://localhost:8000/api/live/file?path=/absolute/path/to/auth.log&start_at_end=false
ws://localhost:8000/api/live/folder?path=/absolute/path/to/log-folder&pattern=*.log&start_at_end=false
ws://localhost:8000/api/live/docker?container=my-container&tail=50
```

## Success Criteria

- Evidence lines are visible.
- MITRE techniques are shown.
- The LLM summary references evidence.
- The report is understandable without opening the app.
- Docker Compose validates with `docker compose config`.
- Backend tests and frontend build pass before recording screenshots.
