# Current Public-Demo Safety Proof

> Status: local and live Azure proof complete on 2026-07-13
> Scope: anonymous session-only analysis, capability isolation, tutorial, and separate deployment

## Claims Under Test

The public demo:

- accepts only bounded UTF-8 text through `/api/public-demo/*`;
- never initializes or writes the private SQLite investigation lifecycle;
- returns no reusable analysis identifier and exposes no result-history lookup;
- disables external AI, host-connected live sources, notes, settings, retention, backup, audit, and
  private report formats;
- marks responses non-cacheable;
- clears browser-held evidence on explicit clear, refresh, tab close, or 30-minute inactivity;
- renders one tutorial registry through eight per-view learning chapters and contextual guided
  walkthroughs, with worked examples and explicit control behavior;
- serves eight self-hosted, English male-narrated walkthroughs with English captions, generated
  only from the fixed sanitized SSH sample and never from visitor uploads.

## Executable Evidence

| Boundary | Evidence |
| --- | --- |
| Profile and route isolation | `apps/api/tests/test_public_demo.py` |
| No SQLite row delta | `test_public_analysis_is_stateless_and_non_cacheable` |
| Bytes, lines, content, rate, concurrency, timeout | focused public API tests |
| Private HTTP and WebSocket denial | public-profile route-isolation tests |
| Public/private frontend capability split | `apps/web/src/app/main.test.tsx` |
| Tutorial registry, accessibility, and keyboard behavior | `apps/web/src/features/tutorial/TutorialExperience.test.tsx` |
| MP4, WebVTT, voice, duration, and manifest integrity | `apps/api/tests/test_proof_assets.py` |
| Reproducible sanitized recordings | `apps/web/scripts/generate-tutorial-videos.mjs` |
| Browser lifecycle and direct tutorial route | `apps/web/e2e-public/public-demo.spec.ts` |
| Isolated no-volume Compose profile | `apps/api/tests/test_public_defaults.py` |
| Exact live deployment contract | `tools/verify_public_demo.py` |

## Local Reproduction

```bash
.venv/bin/python -m pytest apps/api/tests/test_public_demo.py -q
npm --prefix apps/web test -- --run
npm --prefix apps/web run test:e2e:public
make verify-all
```

Local result on 2026-07-13: `make verify-all` passed with 235 backend tests at 89.11% coverage,
38 frontend tests, five private Chromium workflows, two public Chromium workflows, 33 scenario
contracts, all 66 rule contracts, and all documentation, Compose, benchmark, and smoke gates. The
independent local public verifier also returned `database=disabled`, `private_api_status=404`,
`stored=false`, `external_ai=false`, and `tutorial_video_count=8`.

## Live Deployment Evidence

The public-demo implementation, deployment fixes, learning-tool expansion, and narrated tutorial
videos are merged through GitLab MRs `!42`-`!50`.
The exact deployed application commit is
`98555d917ceb2e4f97b33c69489dd8ee260ebcfe`.

| Evidence | Result |
| --- | --- |
| MR validation | MR `!50`, pipeline `2673069015`, all five validation/security jobs passed |
| Main pipeline | `2673100211`, all nine jobs passed |
| Azure preflight | job `15318963880`, managed environment access passed |
| Immutable image build | job `15318963886`, commit tag `98555d9` pushed |
| Private deployment regression | job `15318963887`, exact commit and authenticated API boundary passed |
| Public deployment | job `15318963888`, separate Container App update and extended live verifier passed |
| Public FQDN | `https://ca-tracehawk-public-demo.bluebush-2bdd630a.germanywestcentral.azurecontainerapps.io/` |

The CI live verifier and a second independent local invocation returned:

```json
{
  "build_commit": "98555d917ceb2e4f97b33c69489dd8ee260ebcfe",
  "database": "disabled",
  "deployment_profile": "public_demo",
  "external_ai": false,
  "private_api_status": 404,
  "status": "ok",
  "stored": false,
  "tutorial_video_count": 8
}
```

The independent private regression verifier returned `auth_mode=azure_easy_auth`,
`protected_status=401`, `runtime_mode=azure-container-apps`, 66 loaded rules, five loaded
correlation patterns, healthy database readiness, and the same exact build commit.

Live browser verification proved the visible contract after deployment:

- an anonymous sanitized sample produced 12 raw lines, 12 events, four findings, and one incident;
- `/tutorial` rendered eight separate learning chapters with per-panel explanations, worked
  interpretations, data boundaries, and view-specific control behavior;
- the common-controls chapter documented navigation, intake, search, privacy, and help controls
  with separate `When used` and `Result` explanations;
- the Evidence chapter opened a four-step walkthrough with Back, Restart, Skip, and Next;
- advancing changed the announced state from `Evidence: 1 / 4` to `Evidence: 2 / 4` and explained
  how finding cards change evidence context and how Rule opens the transparent rule definition;
- all eight chapters exposed a separate `Watch ... narrated video` control;
- the live Evidence video loaded the self-hosted MP4 and default English WebVTT captions, reported
  `readyState=4`, and exposed its exact 81.968-second duration through the native player;
- refreshing cleared the analysis and tour, returned `No active result`, and reset findings to zero.

## Limits

- Process-local rate and concurrency controls require a maximum of one public replica.
- In-memory request processing is not equivalent to zero processing; bounded content exists in
  process memory while the request is evaluated.
- `no-store` instructs clients and intermediaries not to retain responses but cannot control a
  visitor who intentionally copies their own result.
- Tutorial MP4 and WebVTT files are static product assets and may be browser-cached; they contain no
  visitor evidence. Loading a video consumes approximately 1.6-2.1 MB of bandwidth.
- This is a demonstration workflow, not tenant-isolated storage or a production SIEM.
