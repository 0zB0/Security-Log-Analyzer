## Problem

Describe the concrete defect or capability gap.

## Change

Describe the smallest behavioral change that resolves it.

## Verification

- [ ] `make verify-all`
- [ ] Relevant focused tests are included or updated
- [ ] Documentation and proof assets match the behavior

## Public-safety checklist

- [ ] No credentials, tokens, cookies, private keys, production logs, client data, or personal data
- [ ] No internal hostnames, private infrastructure details, local filesystem paths, or real synthetic attribution targets
- [ ] Sample IPs use RFC 5737 ranges unless an external dataset is explicitly cited
- [ ] Security-sensitive behavior and residual limitations are documented
- [ ] Vulnerability details were submitted privately instead of in this pull request
