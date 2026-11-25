# HTTP API

`deniz serve` exposes the API. Loopback binds are open by default; setting
`DENIZ_API_TOKEN` or a token file protects every route except `/health`.
Send `Authorization: Bearer <token>` (or `?token=` for the dashboard).

Tokens live in `DENIZ_API_TOKENS` (JSON) or `~/.deniz/tokens.toml` and carry
a role: `viewer` (GET), `operator` (GET/POST) or `admin` (all, including
DELETE). The legacy single token is admin. Missing tokens get `401`; a role
that may not use the method gets `403`.

Browser origins are `*` by default. Restrict with `--cors-origin` or
`DENIZ_CORS_ORIGINS` (comma separated); disallowed origins get no
`Access-Control-Allow-Origin` header.

The server is single-process, read-mostly and meant for a trusted network
behind TLS. Response bodies are JSON unless noted.

Rate limit: 5 requests/second per client IP with a burst of 30; excess gets
`429` and `Retry-After: 1`. `/health` is exempt.

CORS: every response carries an allowed origin header when the origin is
permitted; `OPTIONS` answers preflight without auth.

List endpoints accept `limit` and `offset` and return `X-Total-Count` and
`X-Offset` headers. They also accept an opaque `cursor` and return
`X-Next-Cursor` while more items remain. A cursor wins over an offset; it is
bound to the endpoint and its filters, so reusing it elsewhere returns `400`.
Cursors remember the last sort key, which keeps the next page stable when new
items arrive. Tokens are base64url JSON, not secrets. Limits are capped at 100
for cases/alerts/findings, 500 for case observation search and 1000 for runs.

## Old REPL routes

The former Flask API is gone. Two old routes answer `410` with a typed
replacement hint:

| Route | Replacement |
|---|---|
| `GET /api/framework?command=` | `deniz domain` / `search` / `vuln` / `run` |
| `GET /api/modules?_module=` | `deniz run <provider> <value> --type <kind>` |

`GET /api` lists the live routes.

## Read

| Route | Result |
|---|---|
| `GET /health` | `{"ok": true}`, no auth |
| `GET /` | HTML dashboard |
| `GET /api/stats` | case/run/alert/finding counts |
| `GET /api/audit[?actor&action]` | audit entries (limit/offset, total header) |
| `GET /api/schema` | result JSON Schema |
| `GET /api/providers` | capabilities, auth and 7-day health |
| `GET /api/cases[?archived]` | cases (limit/offset/cursor) |
| `GET /api/cases/<id>` | scope, notes, runs |
| `GET /api/cases/<id>/search?q=` | case-scoped observation search (limit/offset/cursor) |
| `GET /api/runs[?limit]` | run directory names (limit/offset/cursor) |
| `GET /api/runs/<id>` | full result envelope |
| `GET /api/graph/<value>` | entity, observations, edges |
| `GET /api/alerts[?acked]` | alerts (limit/offset/cursor) |
| `GET /api/findings?case=<id>[&acked]` | findings (limit/offset/cursor) |

## Write

| Route | Body |
|---|---|
| `POST /api/cases` | `{"name": "...", "allow": [], "deny": []}` |
| `POST /api/cases/<id>/archive` | empty |
| `POST /api/cases/<id>/unarchive` | empty |
| `POST /api/cases/<id>/export` | `{"redact": false}`, writes zip |
| `POST /api/runs/<id>/report` | `{"redact": false}`, writes HTML |
| `DELETE /api/cases/<id>` | empty |
| `POST /api/monitor` | `{"case": "...", "kind": "domain", "target": "...", "every": 60}` |
| `POST /api/monitor/<id>/run` | empty |
| `POST /api/monitor/tick` | empty |
| `POST /api/alerts/ack` | `{"id": "..."}` or `{"all": true}` |
| `POST /api/findings/refresh` | `{"case": "..."}` |
| `POST /api/findings/ack` | `{"id": "..."}` or `{"all": true, "case": "..."}` |
| `POST /api/findings/set` | `{"id": "...", "severity": "high", "note": "..."}` |

## Examples

```bash
TOKEN=...
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/api/stats

curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"acme","allow":["acme.com"]}' http://127.0.0.1:8787/api/cases

curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"case":"acme","kind":"domain","target":"acme.com","every":60}' \
  http://127.0.0.1:8787/api/monitor
```

## Python client

```python
from deniz.client import Client

with Client("http://127.0.0.1:8787", token="...") as client:
    case = client.create_case("acme", allow=["acme.com"])
    monitor = client.add_monitor(case["id"], "domain", "acme.com", every=60)
    client.run_monitor(monitor["id"])
    print(client.findings(case["id"]))
    print(client.export_case(case["id"]))
```

## Limits

- Offset pagination is capped; cursor pagination is available on list
  endpoints.
- No multi-user auth or roles.
- Findings severity overrides apply to the effective severity in lists and
  exports.
