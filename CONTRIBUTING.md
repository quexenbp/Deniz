# Contributing

Thanks for helping. New work targets `deniz/kit`; the old module tree is gone.

## Setup

The fastest route is the devcontainer (`.devcontainer/README.md`). Manual:

```bash
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest -q
```

Generate a provider instead of copying an existing one:

```bash
python -m deniz new-provider my_source --title "My source"
```

Optional extras: `.[browser]` for PDF and social search, `.[tor]` for onion
access, `.[postgres]` for a shared database.

## Gates

Every change must pass:

```bash
python -m ruff check deniz/kit deniz/cli.py deniz/mcp.py tests
python -m mypy deniz/kit --follow-imports=skip
python -m pytest -q
```

`pre-commit install` runs the formatters automatically.

## Adding a provider

Read [`docs/plugins.md`](docs/plugins.md) and
[`docs/compatibility.md`](docs/compatibility.md). In-tree providers live in
`deniz/kit/providers/`:

1. Subclass `Provider`, declare a unique `ProviderInfo` and
   `API_VERSION = CONTRACT_VERSION`.
2. Return `Observation`s with at least one `Source`; never print.
3. Raise a typed error from `deniz.kit.errors` instead of returning fake data.
4. Register the class in `registry.BUILTIN` (the generator does this).
5. Add a mock-transport test with realistic fixtures, including a failure case.
6. Document auth, cost, rate and ToS in `ProviderInfo`.

Scrapers are allowed, but API-first is preferred. A provider with no test and
no failure handling will be sent back. See [`docs/testing.md`](docs/testing.md)
for cassettes, the nightly canary and load tests.

## Findings

If a provider emits something actionable, add a rule in `findings.derive` with
a conservative severity and a test. Do not invent severity scales; use
critical/high/medium/low/info.

## Style

- Python 3.11+, type annotations on new code.
- Ruff formatting, line length 100.
- No new dependency without a reason; prefer stdlib.
- Comments explain *why*, not *what*.

## Commits

Conventional-ish: `provider: add X`, `fix: ...`, `docs: ...`. One logical
change per commit. Reference the issue when one exists.

## Licensing

Contributions are GPL-3.0-or-later. By submitting you confirm you have the
right to license the code under those terms (inbound = outbound). Keep SPDX
headers on new files.

## Security

Do not paste live API keys in tests. Use `providers.toml.example` for shape.
Report vulnerabilities via `SECURITY.md`.
