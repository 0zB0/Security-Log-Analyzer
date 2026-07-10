# Kubernetes Audit Ingest

TraceHawk accepts exported Kubernetes audit events as UTF-8 JSON Lines. Native cluster collection is outside this slice; the input is a local file where every line is one `audit.k8s.io/*` `Event` object.

## Parser

The `kubernetes_audit` parser recognizes records with `apiVersion` starting with `audit.k8s.io/` and `kind` equal to `Event`.

Normalized event behavior:

- `event_type` is built from `verb`, `objectRef.resource`, and optional `objectRef.subresource`;
- `username` comes from `user.username`;
- `source_ip` is the first item from `sourceIPs`;
- `host` is the Kubernetes namespace when present;
- all nested fields are flattened for rule matching;
- pod create requests mark `privileged_container` when a container has `securityContext.privileged: true`.

## Detection Pack

The Kubernetes rules cover:

- pod exec requests;
- secret get/list/watch access;
- cluster role binding creation;
- privileged pod creation;
- repeated forbidden API requests grouped by username and source IP.

## Local Sample

```bash
curl -F "file=@packages/sample-data/kubernetes/audit-risk.jsonl" \
  http://localhost:8000/api/analyze/upload
```

The same sample is available in the UI sample selector as `Kubernetes audit risk`.
