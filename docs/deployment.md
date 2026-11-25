# Deployment

## Container

```bash
docker compose build
docker compose run --rm deniz version
docker compose run --rm deniz domain example.com --max-hosts 20
```

For PDF output use the `pdf` target (adds Chromium, several hundred MB):

```bash
docker build --target pdf -t deniz:pdf .
docker run --rm -v deniz-data:/data deniz:pdf report <run-id> --format pdf
```

The same image is aliased `browser` and is also the only image with the
Chromium needed by `deniz social`.

The image runs as UID 10001, keeps state in the `deniz-data` volume and does
not use `latest`. Pin a digest in production.

For a long-running monitor loop:

```yaml
command: ["monitor", "daemon", "--poll", "60"]
restart: unless-stopped
```

### SearXNG

The compose file ships an optional SearXNG service:

```bash
docker compose --profile search up -d searxng
docker compose run --rm -e DENIZ_SEARXNG_URL=http://searxng:8080 deniz search "query"
```

SearXNG gives an API-ish search backend without Google scraping. Keep the port
bound to loopback.

## Secrets

Prefer environment variables in production:

```bash
DENIZ_CERTSPOTTER_TOKEN=...
DENIZ_SEARXNG_URL=https://searx.internal
DENIZ_WEBHOOK_URL=https://hooks.internal/deniz
DENIZ_WEBHOOK_STYLE=slack
# DENIZ_PROXY=socks5h://tor:9050
```

Inside the container the file at `/data/providers.toml` works too; mount it
read-only at `/data/providers.toml`.

## Cron

`monitor tick` is idempotent for the due window and exits. A cron entry is
enough when no daemon is wanted:

```cron
*/5 * * * * deniz monitor tick --limit 50
```

## Health

```bash
deniz doctor
deniz providers list
```

`doctor` exits non-zero on failed checks. Provider health is a rolling 7-day
ratio; a provider at 0% is sorted last in the subdomain fallback chain. With
`DENIZ_PROXY` or `DENIZ_DB_URL` set, `doctor` also probes the proxy port and
runs `SELECT 1`.

## Dashboard

```bash
DENIZ_API_TOKEN=... deniz serve --host 0.0.0.0 --port 8787
```

The API is read-only except the `POST` endpoints. Put TLS in front; the
token travels in a bearer header (or `?token=` for the dashboard). The
dashboard lets you create cases, add monitors and acknowledge alerts without
a terminal.

The old REPL `web api` route now starts this server. `/api/modules` and
`/api/framework` answer `410` with typed replacements.

Client IPs are limited to 5 req/s with a burst of 30. The server keeps limits
in memory; restarting it resets the buckets.

## Postgres

SQLite is the default. Set `DENIZ_DB_URL` to use Postgres for cases, graph,
monitors and findings:

```bash
pip install "deniz[postgres]"
export DENIZ_DB_URL="postgresql://deniz:secret@db:5432/deniz"
deniz doctor
```

The HTTP cache stays SQLite. Migrate with `deniz backup` / `deniz restore`
against the new DSN. Postgres keeps the same single-writer model; one daemon
per database.

```bash
docker compose --profile postgres up -d postgres
docker compose run --rm -e DENIZ_DB_URL=postgresql://deniz:secret@postgres:5432/deniz deniz doctor
```

Change the default `secret` before exposing anything.

## Backups

State is seven SQLite databases plus run directories under
`$DENIZ_HOME`: `cache.sqlite3`, `state.sqlite3`, `graph.sqlite3`,
`cases.sqlite3`, `monitors.sqlite3`, `findings.sqlite3`, `audit.sqlite3` and
`runs/`. Prefer the built-in commands:

```bash
deniz backup /backups/$(date +%F)
deniz restore /backups/2026-11-22 --force
```

The cache is disposable. `providers.toml` is not part of the backup; store it
separately. `audit.sqlite3` is included and can also be pruned with
`deniz audit prune --days 180 --yes`.

## Binary

```bash
bash scripts/build-binary.sh        # Windows: .\scripts\build-binary.ps1
```

The PyInstaller build is one file with the bundled wordlists. It is a
convenience for operators, not a signed artifact; releases still sign the
wheel and sdist.

## Kubernetes and workers

`deploy/k8s/deniz.yaml` contains an API deployment, two monitor workers, a
PVC and a backup CronJob. Workers are safe to scale because due monitors are
claimed with a Postgres lease. See `deploy/k8s/README.md`.

The compose equivalent:

```bash
docker compose --profile postgres --profile workers up --scale worker=2
```

## Auth and CORS

`DENIZ_API_TOKEN` remains a single admin token. For roles, set
`DENIZ_API_TOKENS` (JSON list) or edit `tokens.toml`:

```toml
[[tokens]]
name = "dashboard"
value = "..."
role = "viewer"

[[tokens]]
name = "automation"
value = "..."
role = "operator"
```

Roles are `viewer` (GET), `operator` (GET/POST) and `admin` (all). Restrict
browser origins with `--cors-origin` or `DENIZ_CORS_ORIGINS`; the default `*`
is suitable only for loopback or a token-gated API.

## Limits

- Single-writer SQLite. One daemon per `DENIZ_HOME`; use Postgres for several
  workers.
- Multi-user auth is a shared token per role; there are no per-object ACLs.
  Terminate TLS and put identity-aware auth in front if needed.
- `http_probe` stops at 600 KB per response; heavy providers declare their own
  per-response cap and run budget (`docs/providers.md`).
- `social` needs `pip install 'deniz[browser]' && playwright install chromium`.
  Its Chromium trusts system CAs by default and accepts broken interception
  certs unless `DENIZ_BROWSER_STRICT_TLS=1`.
