# Status

Version: 0.1.0.

## Current surface

- 67 providers across certificates, DNS, HTTP, ASN, RDAP, buckets, breaches,
  identities, files, search engines, social sites, Turkish disclosures and
  precedent search.
- Typed result envelope with provenance, per-provider budgets, cache, rate
  limits and a health ledger with quarantine.
- Domain, search, vulnerability and social pipelines; entity graph; cases,
  findings, monitors and webhook alerts.
- HTML, STIX 2.1, JSONL and PDF reports; redaction and retention.
- Audit trail, token roles, configurable CORS, cursor pagination.
- MCP over stdio or HTTP with SSE progress.
- Trusted Publishing workflow, container image, Kubernetes manifests and
  worker scaling on Postgres leases.

## Verification

- 233 tests, one opt-in Postgres test skipped.
- `ruff` and `mypy` clean.
- OpenAlex and Discord live checks pass.
- PyPI artifact dry-run passes.

## Known limits

- MCP HTTP sessions are in memory; a restart drops them.
- Roles have no per-object ACLs: any operator can write any case.
- KAP and UYAP are not calibrated on an unfiltered network. MERSİS and the
  Trade Registry Gazette remain manual.
- Six social sites hit login, consent or JS walls; Discord parses.
- crt.sh 502s often; Cert Spotter's unauthenticated quota is low.
- Case observation search and `graph.search` cap at 10,000 rows.
- PDF needs Chromium; the browser extra is optional.

## Next

1. Publish 0.1.0 to TestPyPI, then PyPI.
2. Re-run social calibration with `DENIZ_BROWSER_STATE` cookies.
3. Send the OWASP note.
