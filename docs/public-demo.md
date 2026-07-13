# Session-Only Public Demo

TraceHawk has two deliberately different deployment profiles:

| Profile | Audience | Authentication | Persistence | Host capabilities |
| --- | --- | --- | --- | --- |
| `private` | local analyst or allowlisted Azure user | local trust or Azure Easy Auth | SQLite enabled | role-gated |
| `public_demo` | anonymous visitor | no account | disabled | unavailable |

The public demo is not the private workspace with authentication removed. It is a capability-
reduced runtime that exposes only health/version metadata, the read-only rule library, static UI,
and `/api/public-demo/*`.

## Evidence lifecycle

```text
browser reads one text file
-> bounded JSON request
-> in-memory parser/detection/correlation
-> non-cacheable AnalysisResult response
-> React memory
-> clear, refresh, tab close, or 30-minute inactivity timeout
```

The public endpoint has no SQLAlchemy `Session` dependency and never calls `persist_analysis`.
Original files, raw evidence, parsed events, findings, incidents, entities, and generated Markdown
are not written to server-side history. Responses include `Cache-Control: no-store` and explicitly
report `stored=false` and `external_ai=false`.

No general-purpose “recent runs” endpoint is exposed. Two visitors cannot query each other's
results because the server has no public result store or public analysis identifier.

## Public limits

- one `.log`, `.txt`, `.csv`, `.json`, or `.jsonl` file;
- 512 KiB maximum UTF-8 payload;
- 20,000 lines maximum;
- five public actions per ten-minute client window;
- two concurrent analyses per process;
- ten-second execution timeout;
- NUL, control-heavy, binary, compressed, archive, and unsupported input rejection;
- one initial replica so the process-local rate/concurrency controls have an explicit boundary.

The browser reads text and sends JSON instead of multipart upload. This avoids a framework upload
spool becoming a temporary server-side file. Request logs contain route/status/timing metadata but
never request bodies or evidence.

## Available UI

Anonymous visitors may use Upload, Incidents, Findings, Evidence, Entities, MITRE, Markdown Reports,
the read-only Detection Library, and the Guided Tutorial. The public UI and server both disable:

- saved runs and case history;
- case bundles and real-lab imports;
- live file/folder, Docker, interface, and syslog sources;
- Local AI and assistant settings;
- notes, retention, backup, audit, and admin settings;
- server-side PDF/HTML report generation.

The persistent privacy banner shows the session boundary and inactivity countdown. `Clear session`
removes the result, selections, search, and report from React state. The UI does not write evidence
to `localStorage`, `sessionStorage`, IndexedDB, URLs, or analytics.

## Guided tutorial

`/tutorial` and every contextual question button render from one registry in
`apps/web/src/features/tutorial/tutorialRegistry.ts`. The page is an eight-chapter learning tool:
Upload, Incidents, Findings, Evidence, Entities, MITRE, Reports, and Detection Library. Every
chapter explains:

1. its purpose;
2. every display or panel and what it shows;
3. a worked example that connects an observation to an interpretation and next step;
4. every view-specific button, field, selector, and toggle, including the result of using it;
5. where its data comes from, how to read it, and the interpretation limit;
6. the exact UI controls in a keyboard-accessible guided walkthrough.

A separate common-controls chapter documents navigation, global search, session clearing, sample
analysis, file selection, Markdown shortcuts, and contextual help. Stable `data-tour` targets bind
the walkthrough steps to the real controls and panels instead of duplicating a second UI.

Each chapter also contains a separate 60–90 second narrated video. The recordings use the English
`en-US-GuyNeural` male voice, visible click indicators, on-video narration text, and English WebVTT
captions. They are generated only from the fixed sanitized SSH sample; visitor uploads are never
used for recordings. Videos are lazy-loaded after an explicit click and served directly by the
TraceHawk deployment without analytics or a third-party video player.

Regenerate the checked-in MP4, caption, and manifest assets with:

```bash
npm --prefix apps/web run generate:tutorial-videos
```

The generator uses Playwright, pinned `edge-tts==7.2.8`, FFmpeg, and a fresh local public-demo
process per video so the normal public rate limit remains enforced.

Tour progress is component state only. Tutorial prose never copies visitor evidence.

## Local verification

```bash
docker compose --profile public-demo up --build
```

Open `http://localhost:8001`. The Compose profile has no volume, uses a read-only container
filesystem plus a bounded temporary filesystem, disables external AI, and publishes only on host
loopback.

Run the complete browser proof:

```bash
npm --prefix apps/web run test:e2e:public
```

Run live contract verification against a deployed demo:

```bash
.venv/bin/python tools/verify_public_demo.py \
  --url https://demo.example.invalid \
  --expected-commit "$(git rev-parse HEAD)"
```

The verifier checks the exact commit, public profile, disabled database readiness check, non-cache
headers, private API denial, stateless repeated analysis, no public analysis ID, disabled external
AI, and the tutorial route.
