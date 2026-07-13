# Current API Contract And Frontend Verification Proof

Captured: 2026-07-13

## Result

The FastAPI-to-browser contract is deterministic and drift-enforced. Core frontend response types
are imported from generated declarations. Primary analyst behavior is covered by interaction,
axe, and built-application Chromium tests.

## Contract Evidence

| Control | Result |
| --- | --- |
| Deterministic OpenAPI export | `apps/web/src/generated/openapi.json` generated from `app.openapi()` with stable ordering |
| TypeScript generation | `apps/web/src/generated/api-schema.ts` generated without a JavaScript code-generation dependency |
| Drift gate | `python tools/generate_api_contract.py --check` passed |
| Required schemas | Backend regression asserts analysis, finding, incident, evidence integrity, assistant, report, note, and rule models |
| Frontend use | `apps/web/src/lib/api.ts` consumes generated core response types |
| CI enforcement | GitLab and GitHub backend jobs run the drift check |

## Interaction Evidence

| Layer | Measured result | Behavior covered |
| --- | --- | --- |
| Vitest / Testing Library | 38 tests in 12 files | private intake/recovery, case/evidence/report behavior, public capability isolation, pre-read size rejection, inactivity clearing, fail-closed profile loading, tutorial registry, guided-tour keyboard behavior, and primary axe states |
| axe | zero violations in asserted primary component/application states | main workspace, incident, evidence, metrics, settings, live, and case states |
| Playwright Chromium | 5 private + 2 public tests | private report/admin/real-lab/evidence/recovery paths plus anonymous stateless upload, refresh clearing, restricted controls, contextual help, Escape handling, and direct tutorial routing |
| TypeScript/Vite | production build passed | generated aliases and maintained frontend compile together |

Whole-source V8 coverage after the behavior tests:

| Metric | Measured | Enforced floor |
| --- | ---: | ---: |
| Statements | 74.08% | 70% |
| Branches | 61.93% | 50% |
| Functions | 71.70% | 65% |
| Lines | 75.46% | 70% |

Coverage includes maintained `src` TypeScript/TSX and excludes tests, declarations, test support,
and generated type-only artifacts. GitLab and GitHub retain the HTML, LCOV, and summary coverage
outputs. Both CI systems retain Playwright report, trace, screenshot, video, and test-result paths
when produced.

## Negative And Recovery Evidence

- A modified or otherwise rejected live snapshot save surfaces the server error and a following
  valid retry succeeds.
- A failed analysis clears stale analysis state, displays the server detail, and a following
  request restores the investigation without a page reload.
- A report failure clears stale report output.
- Settings load and update failures remain visible instead of showing an endless loading state.
- A rule filter with zero matches renders an explicit empty detail instead of an unrelated rule.

## Reproduction

```bash
make api-contract-check
.venv/bin/python -m pytest apps/api/tests/test_api_contract.py -q
npm --prefix apps/web run test:coverage
npm --prefix apps/web run build
npm --prefix apps/web run test:e2e
npm --prefix apps/web run test:e2e:public
```

## Boundary

These results prove the committed Chromium critical paths and selected axe states. They do not
prove every browser, every responsive size, exhaustive screen-reader behavior, or runtime schema
validation of a compromised backend response.
