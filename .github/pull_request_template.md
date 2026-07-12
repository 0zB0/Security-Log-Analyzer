## Problem

Describe the concrete defect or capability gap.

## Change

Describe the smallest behavioral change that resolves it.

## Verification

- [ ] `make verify-all`
- [ ] Relevant focused tests are included or updated
- [ ] Documentation and proof assets match the behavior

Provide the red/green boundary: name the test or reproduction that failed before the change and the
exact command that passes afterward.

## Security and data impact

Describe authentication, persisted-schema, evidence-retention, false-positive, performance, and
deployment impact. Use `None` only after checking each boundary.

## AI assistance

- [ ] No substantive AI assistance was used, or its model/tool, scope, and manual verification are
      disclosed below

<!-- Describe AI-assisted design, code, tests, debugging, or documentation. Do not paste secrets or confidential prompts. -->

State which generated claims or changes were independently checked and how the contributor can
explain or modify them.

## Public-safety checklist

- [ ] No credentials, tokens, cookies, private keys, production logs, client data, or personal data
- [ ] No internal hostnames, private infrastructure details, local filesystem paths, or real synthetic attribution targets
- [ ] Sample IPs use RFC 5737 ranges unless an external dataset is explicitly cited
- [ ] Security-sensitive behavior and residual limitations are documented
- [ ] Vulnerability details were submitted privately instead of in this pull request
