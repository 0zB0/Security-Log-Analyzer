# Generated API Contract

> Audience: backend, frontend, and CI maintainers
> Canonical for: FastAPI-to-TypeScript schema generation and drift enforcement

TraceHawk treats the FastAPI OpenAPI document as the source of truth for shared HTTP response
models. The browser does not maintain independent copies of core analysis, finding, incident,
evidence, assistant, report, note, and rule-library schemas.

## Artifacts

| Path | Purpose |
| --- | --- |
| `apps/web/src/generated/openapi.json` | Canonical, key-sorted OpenAPI snapshot exported from the running FastAPI application object |
| `apps/web/src/generated/api-schema.ts` | Deterministic TypeScript declarations generated from OpenAPI component schemas |
| `tools/generate_api_contract.py` | Dependency-free generator and drift checker |
| `apps/web/src/lib/api.ts` | Request helpers plus frontend-resolved aliases around generated response types |
| `apps/api/tests/test_api_contract.py` | Backend-side artifact and required-schema regression tests |

The TypeScript generator supports references, unions, intersections, constants, enums, arrays,
objects, required properties, and typed maps used by the current Pydantic schema. Unsupported
external references fail generation rather than silently producing an invented domain type.

## Workflow

Regenerate after changing a Pydantic request or response model:

```bash
make api-contract
npm --prefix apps/web run build
```

Prove that committed artifacts match the current backend:

```bash
make api-contract-check
```

`--check` generates both files in memory, compares exact bytes, prints a unified diff, and exits
non-zero on drift. `make verify-all`, GitLab backend validation, and GitHub backend validation run
this check. A backend contract change therefore cannot merge with stale browser declarations.

## Frontend Consumption

`apps/web/src/lib/api.ts` imports generated component types and applies `Required` or explicit
nested overrides where FastAPI always serializes Pydantic defaults. This keeps browser-facing
values ergonomic without copying the field names or literal unions into a second contract.

The auth-status object and live WebSocket envelope remain explicit frontend types because they are
not emitted as reusable OpenAPI component schemas. They are tested at their HTTP/WebSocket
boundaries. If those surfaces become shared HTTP models, they should move into Pydantic and the
generated contract.

## Security And Runtime Boundary

Generated TypeScript is compile-time evidence, not runtime validation of an untrusted response.
Authorization, upload validation, live attestation, evidence integrity, parsing, detection,
correlation, and persistence remain backend responsibilities. UI role-based hiding is defense in
depth and never replaces server authorization tests.
