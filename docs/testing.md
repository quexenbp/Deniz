# Testing and quality

## Default gate

```bash
python -m pytest -q -m "not load"
python -m ruff check deniz/kit deniz/cli.py deniz/mcp.py tests
python -m mypy deniz/kit --follow-imports=skip
```

Unit tests use `httpx.MockTransport` and never touch the network. Load tests
carry the `load` marker and run in a separate CI job.

## Contract tests

Every provider needs at least a parse test and a failure test. The generator
(`deniz new-provider`) writes both. A provider without a failure path is sent
back in review.

## Recorded fixtures

Stable JSON APIs may use a VCR cassette instead of hand-written mocks:

```bash
python -m pytest tests/test_recorded_openalex.py -q --record-mode=once
```

Cassettes live under `tests/cassettes/` and are committed. The default mode
replays them, so CI stays offline. Re-record when the upstream shape changes
and include the cassette diff.

## Canary

`scripts/canary.py` runs one keyless query per provider against the live
network and records the health ledger. It exits non-zero below 50% success.
The `canary` workflow runs nightly and uploads JSON; local use:

```bash
python scripts/canary.py --only openalex --json
```

A provider with at least five samples and under 50% success is hidden from
`deniz providers list` (use `--all`) and from `search` candidates.

## Load and soak

```bash
python -m pytest -q -m load
```

Thresholds are intentionally loose (seconds, not milliseconds); they catch
quadratic regressions, not micro-noise. Use a disposable `DENIZ_HOME` for
manual soak runs.

## Coverage

CI enforces a floor. New code should raise it; do not add exclusions to make a
number pass. Report gaps in the PR instead.
