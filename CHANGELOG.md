# Changelog

## 0.1.0 — 2026-11-25

First release. The package, module and command are `deniz`.

### Added

- `social` provider and `deniz social`: site-scoped search on Instagram,
  TikTok, LinkedIn, Facebook, Quora, Trello and Discord through headless
  Chromium (`[browser]` extra). MCP `deniz_social` mirrors it.
- Per-provider response caps and run byte budgets (`ProviderInfo.max_bytes`,
  `ProviderInfo.budget`), enforced in `ProviderHttp`; heavy scrapers declare
  limits and the provider catalog shows them.
- `DependencyMissing` and `BudgetExceeded` typed errors.
- Cursor pagination on the list API endpoints and MCP list/search tools:
  scope-bound opaque tokens, `X-Next-Cursor` / `next`, stable under inserts.
- Cursor pagination for MCP case and monitor lists and the case observation
  search API.
- Alert cursors page in SQL with a real `COUNT`, replacing the 10,000-row cap.
- PII redaction for reports and case exports (`--redact`, `redact` body flag):
  e-mail local parts and phone numbers, including attributes, sources, findings
  and notes. Turkish report labels via `--lang tr` / `DENIZ_LANG`.
- Retention commands: `case prune --days`; audit pruning and docs.
- Audit log (`audit.sqlite3`) written by CLI, API and MCP, with
  `deniz audit list` and `GET /api/audit`; included in backups.
- API token roles (`viewer`/`operator`/`admin`) from `tokens.toml` or
  `DENIZ_API_TOKENS`, and configurable CORS origins.
- MCP over HTTP with SSE responses and `notifications/progress`.
- KAP and UYAP providers for Turkish disclosures and precedent search.
- PyInstaller spec and build scripts; Kubernetes manifests; compose
  `api`/`worker` profiles with Postgres lease scaling.
- `new-provider` scaffold with a contract-test template.
- Devcontainer and 15-minute contributor path.
- Provider contract version (`CONTRACT_VERSION`/`API_VERSION`) with load-time
  validation and a compatibility policy.
- Recorded VCR cassette for OpenAlex and `docs/testing.md`.
- Nightly canary workflow and health-based provider hiding (five-sample floor).
- Load/soak tests and a separate CI job.
- Legacy parity: crawl regex, `search --filetype/--site`, RapidDNS and Anubis
  passive DNS providers, dark-web depth. All 61 legacy modules are mapped.
- Version decision (`docs/versioning.md`), artifact dry-run scripts and
  TestPyPI-first release steps.
- OWASP revival proposal draft in `docs/owasp-proposal.md`.
- Social calibration script and notes; six sites still hit login/consent walls,
  Discord parses when run alone.
- Browser sessions load a Playwright `storage_state` JSON via
  `DENIZ_BROWSER_STATE`, so logged-in social sites can be calibrated.
- Trusted Publishing workflow: TestPyPI/PyPI upload via OIDC, no stored API
  token; tag/version guard and PEP 740 attestations.
- Python client `Page` results with `cases_page`, `alerts_page`,
  `findings_page` and `runs_page`.

### Changed

- MCP `deniz_case` search returns `{total, offset, next, items}` instead of a
  bare array; `deniz_case` list returns `{total, offset, next, cases}` and
  `deniz_monitor` list returns `{total, offset, next, monitors}`.
- Alert cursors are bound to the acked filter and case, so tokens issued before
  this change are rejected.
- The unused `[ml]` extra was removed; embeddings were never wired. The base
  install keeps `vaderSentiment` for offline sentiment.

- `Context` carries `options` for per-run provider settings.
- API responses send permissive CORS headers and `OPTIONS` preflight bypasses
  auth.
- Packaging uses the SPDX `license` string and setuptools 77.

### Removed

- The legacy engine (`deniz/core`, `deniz/modules`), its worker and `web` REPL
  command.
- The old-name console alias and legacy environment, schema and entry-point
  readers.

## 3.0.0.dev0 — 2026-11-22

Foundation release of the community rewrite.

### Added

- Typed `deniz.result/1` envelope, observations with provenance and confidence.
- HTTP client with TLS verification, retries, per-host rate limits and a TTL cache.
- Provider contract, registry and health ledger.
- crt.sh, Cert Spotter, Hackertarget, SearXNG, DNS and HTTP probe providers.
- Typosquat/lookalike resolver (permutations + DNS).
- `deniz domain` attack-surface slice with scope enforcement and run storage.
- `deniz graph` entity/observation/edge store, `runs --diff`, case-scoped views, JSON/CSV export.
- Read-only MCP server (`deniz mcp`) with thirteen schema'd tools.
- Overview stats command and API endpoint.
- Result JSON Schema command and endpoint.
- Probe and discovery parsing capped at 300 KB.
- Optional Textual TUI for cases, alerts and findings.
- Python SDK client.
- Findings: severity rules, overrides, notes, filters, ack state, case export integration.
- Versioned backup and restore with run files.
- Optional Postgres backend for state stores.
- Import of host/URL/IP/identity lists into cases and Nmap XML.
- NVD 2.0 provider and `vuln` search with EPSS enrichment.
- Username enumeration and HIBP breach providers.
- Cloud bucket existence checks (S3, GCS, Azure).
- GitHub repo inventory and code-search leak provider.
- Email authentication posture (SPF, DMARC, DKIM, MX) and common-port TCP check.
- Subdomain takeover candidates, technology fingerprint and security-header audit.
- RDAP registration record and associated expiry/status findings.
- ASN/prefix attribution via Team Cymru DNS.
- robots.txt, sitemap and security.txt discovery.
- Wikipedia, arXiv and Reddit search providers.
- Multi-provider search with round-robin merging.
- URLScan.io search provider.
- Shodan InternetDB IP intel provider.
- Wayback CDX URL history provider.
- Stack Overflow search provider.
- OpenAlex and Photon providers.
- Suggest, DNSBL and Ahmia providers.
- Openverse and TLD variation providers.
- Entry-point extraction and crawl providers.
- Common sensitive-path probe.
- Email discovery provider.
- Phone analysis provider.
- X recent search provider.
- DNS brute force provider.
- PubMed and person profile providers.
- Pastebin, dictionary and SepiaSearch providers.
- Pirate Bay and crt.sh search providers.
- YouTube search provider.
- Telegram, Wikileaks and sentiment providers.
- Spotify search provider.
- Hacker News, Lemmy and Mastodon providers.
- Offline cluster and topic-term providers.
- Dark-web crawl provider with optional Tor proxy.
- Goodreads search provider.
- Health-ordered fallback chain.
- MCP tool pagination for alerts, findings and case search.
- Streaming download caps with a 600 KB probe limit.
- Doctor proxy and database ping checks.
- `runs prune` now drops graph rows; FK-safe entity cleanup.
- `socksio` moved to base dependencies so SOCKS proxies work everywhere.
- GitLab project inventory provider.
- DNS zone transfer provider.
- Cases: CRUD, archive/restore/delete with cleanup, tags, per-case scope, notes, run attachment, search, HTML/JSON/STIX/zip export, timeline.
- Run retention pruning that preserves case runs.
- Monitors: scheduled re-runs, delta alerts, webhook delivery with Slack/Discord styles.
- HTTP API and dashboard with bearer token, write endpoints, inline actions, rate limiting, pagination and export triggers.
- Provider plugins from entry points or `DENIZ_PLUGIN_PATH`.
- Dockerfile, compose file (optional SearXNG profile), pre-commit and deployment notes.
- HTML, STIX 2.1, JSONL and optional PDF report output; case STIX includes finding notes.
- `deniz run` for direct provider calls.
- Provider credentials via environment or `providers.toml`.
- `--offline` cache-only replay.
- CLI: `version`, `doctor`, `providers`, `domain`, `cache`, `runs`, `graph`.
- `scope.toml` allow/deny lists.
- CI on Linux, macOS and Windows.

### Fixed

- Modules could not run on Windows (`cannot pickle 'TextIOWrapper'`).
- DuckDuckGo crashed on HTTP 202 / anti-bot pages.
- `dnsbrute` returned a list where the runner expected a dict.
- crt.sh utility raised on non-JSON responses; now falls back to Cert Spotter.
- `cve_search` used retired NVD 1.0 and MITRE CGI endpoints; now NVD 2.0.
