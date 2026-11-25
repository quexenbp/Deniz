# Architecture

## Layers

```
CLI / TUI / MCP / HTTP API / Python SDK
                  │
        Orchestrator (domain, search, vuln, monitors)
                  │
   Provider registry ── HTTP core ── Cache ── Limiter ── Health
                  │
              Modules (typed providers)
                  │
   Result envelope ── Graph ── Findings ── Cases ── Store
```

## Rules

1. **Providers never print.** They return `Observation`s or raise a typed
   error. The CLI renders.
2. **Every observation has provenance.** `Source` is required by the model.
3. **Budget is declared.** `ProviderInfo` carries rate, burst, auth and cost.
   The HTTP client enforces the rate per host.
4. **Failures are typed.** `Blocked`, `RateLimited`, `ParseChanged`,
   `AuthRequired`, `ProviderDead` drive health, fallback and quarantine.
5. **Scope is explicit.** Nothing outside the target/case scope is probed
   unless a provider marks it as a lookalike.
6. **Storage is append-only per run.** Runs are immutable directories; the
   graph is the durable projection.

## Result envelope

`deniz.result/1` is the only interchange format. It carries the target,
provider, timestamp, items, errors and stats. Reports and the API consume it;
nothing consumes stdout.

## Health and fallback

Each provider call records ok/fail/blocked/parse to a rolling ledger. Domain
collection uses an ordered fallback chain for subdomains. A provider below 50%
should be treated as degraded in the UI and by `monitor` runs.

## Cases

A case groups runs, scope and notes. Findings are derived from run
observations, not hand-written. A case export contains the raw runs, the
derived findings, a timeline and a STIX bundle.

## Why SQLite first

One analyst, one writer, zero operations. Each store goes through `kit/db.py`,
so `DENIZ_DB_URL` swaps in Postgres without changing providers. Backup and
restore speak a versioned JSON format for migration.

## Adding a layer

Before adding a service, ask whether it can be a provider, a finding rule or a
report renderer. New core services need a test proving failure behaviour, not
just the happy path.
