# Audit log

Every state-changing action from the CLI, HTTP API and MCP server is appended
to `audit.sqlite3` (or the Postgres database when `DENIZ_DB_URL` is set).

Each row records time, actor, action, target, outcome and a JSON detail bag.
Reads:

```bash
deniz audit list --limit 50
deniz audit list --event case.delete --json
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8787/api/audit?action=case.delete"
```

Actors are `cli`, `mcp`, `api` (a token without a name) or the configured token
name. Outcomes are `ok` by default; failed monitor runs record `error`.

Retention:

```bash
deniz audit prune --days 180 --yes
```

The log is appended by each process. SQLite serialises writers; with several
workers use Postgres. The log is included in `deniz backup`. It is not signed:
treat it as an operational trail, not tamper-proof evidence.
