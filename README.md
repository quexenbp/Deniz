# Deniz

[![License: GPL-3.0+](https://img.shields.io/badge/License-GPLv3%2B-green.svg)](LICENSE)

Source: <https://github.com/quexenbp/Deniz>

Deniz is an OSINT workbench for attack-surface, identity and document research. It is built around a typed provider core, a graph, cases and agent surfaces.

Providers declare cost, auth, rate and response budget, and every observation keeps its source and confidence. A SQLite cache and per-host token buckets sit under them. Results land in a versioned JSON envelope (`deniz.result/1`) and a graph you can query, diff and monitor.

## Install

Python 3.11 to 3.13.

```bash
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Optional extras: `.[browser]` for PDF and social search, `.[tor]` for onion access, `.[postgres]` for a shared database, `.[tui]` for the console.

## Quick start

```bash
deniz doctor
deniz providers list
deniz domain example.com
deniz domain example.com --json
deniz search "owasp top 10" --filetype pdf --site example.com
deniz vuln log4j --limit 10
deniz identity torvalds
deniz buckets example.com
deniz run openalex "osint" --type keyword
deniz run darkweb "market" --type keyword --depth 2
deniz run kap "tahsis" --type keyword
deniz run uyap "tahliye" --type keyword

deniz case new acme --allow acme.com
deniz domain acme.com --case acme
deniz findings refresh --case acme
deniz report <run-id> --redact --lang tr
deniz case export acme --redact --zip
```

`deniz run crawl example.com --type hostname --regex '[\w.]+@[\w.]+'` extracts matches from crawled pages.

## What it collects

Search providers cover the web, code, papers, video, social sites and Turkish disclosures. OSINT providers handle certificates, DNS, RDAP, ASN, ports, buckets, email auth, breaches, usernames, phones, takeovers and exposed files. Most run through `domain` or `search`; individual providers are always reachable with `run`.

Provider health is recorded per call. A provider with at least five samples and under 50% success is hidden from `providers list` and from search candidates until it recovers. `providers list --all` shows it.

## Results

Each run is a directory under `~/.deniz/runs/` with `result.json`, `items.jsonl`, `errors.jsonl` and `summary.json`. Runs are immutable. The graph is the durable projection: entities, observations and edges, scoped by case.

`deniz graph`, `deniz runs --diff` and case search work on that graph. Reports render HTML, STIX 2.1, JSONL or PDF.

## Cases, findings, monitors

A case holds scope (allow and deny lists), notes, tags and runs. Findings derive from observations, not from typing: takeovers, CVEs, breaches, exposed paths, email-auth gaps and similar rules.

Monitors re-run a profile on a schedule, alert on new entities and deliver to a webhook. Postgres leases keep several workers from running the same monitor twice.

## Agents

`deniz mcp` serves JSON-RPC over stdio or HTTP (`--http`). SSE responses and `notifications/progress` are supported. Tools are prefixed `deniz_` and paginate with `limit`/`offset` or cursor tokens.

```json
{
  "mcpServers": {
    "deniz": { "command": "deniz", "args": ["mcp"] }
  }
}
```

## HTTP API

`deniz serve` starts a read-mostly JSON API and dashboard on loopback. Set `DENIZ_API_TOKEN` before a public bind.

List routes use cursor pagination. Writes and exports are audited. Roles come from `~/.deniz/tokens.toml` or `DENIZ_API_TOKENS`: `viewer`, `operator`, `admin`. CORS origins are configurable with `--cors-origin`.

The Python client is in `deniz.client`.

## Privacy

`--redact` masks e-mail local parts and phone numbers in reports and exports, including attributes, sources and notes. The stored run stays raw.

Retention commands:

```bash
deniz runs prune --prune-days 90
deniz case prune --days 180 --yes
deniz audit prune --days 180 --yes
```

The audit log is at `deniz audit list` and `GET /api/audit`.

## Turkish sources and language

KAP disclosures and UYAP precedent search are built in. `--lang tr` renders Turkish report labels; `DENIZ_LANG=tr` sets the default. MERSİS and the Trade Registry Gazette need e-Devlet or captcha, so they stay manual.

## Deployment

```bash
docker compose --profile serve up
docker compose --profile postgres --profile workers up --scale worker=2
```

Kubernetes manifests are in `deploy/k8s/`. Two PyPI trusted-publisher environments (`testpypi`, `pypi`) carry releases; see `docs/publishing.md`.

## Tests

```bash
python -m pytest -q -m "not load"
python -m pytest -q -m load
python -m ruff check deniz/kit deniz/cli.py deniz/mcp.py tests
python -m mypy deniz/kit --follow-imports=skip
```

New providers get a scaffold and a failing test from `deniz new-provider`.

## Docs

- [Architecture](docs/architecture.md)
- [HTTP API](docs/api.md)
- [Provider catalog](docs/providers.md)
- [Provider plugins](docs/plugins.md)
- [Compatibility](docs/compatibility.md)
- [Deployment](docs/deployment.md)
- [Publishing](docs/publishing.md)
- [Privacy](docs/privacy.md)
- [Audit](docs/audit.md)
- [Testing](docs/testing.md)
- [Turkish sources](docs/turkey.md)
- [Status](docs/v3-status.md)
- [Contributing](CONTRIBUTING.md)

## License

GPL-3.0-or-later. See `LICENSE`.
