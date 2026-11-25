# Provider plugins

Providers are the only extension point that talks to the network. A plugin is
a `Provider` subclass; it runs in-process, so treat the plugin directory as
trusted code.

## Quick start

Generate the skeleton and its contract test:

```bash
python -m deniz new-provider acme --title "ACME lookup"
python -m pytest tests/test_acme.py -q
```

Or create the file by hand:

```python
from deniz.kit.errors import ParseChanged
from deniz.kit.models import Observation, Source, Target
from deniz.kit.providers.base import Context, Provider, ProviderInfo


class Acme(Provider):
    info = ProviderInfo(
        name="acme",
        title="ACME lookup",
        capabilities=frozenset({"identity"}),
        auth="key",
        cost="quota",
        rate=1.0,
        burst=1,
        notes="Example provider.",
    )
    cache_ttl = 900.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "username":
            raise ParseChanged("acme expects a username")
        token = ctx.auth.get("acme")
        resp = self.client.get(
            f"https://api.acme.test/u/{target.value}",
            headers={"authorization": f"Bearer {token}"},
        )
        if resp.status != 200:
            return []
        return [
            Observation(
                type="url",
                value=f"https://acme.test/{target.value}",
                confidence=0.8,
                sources=[Source(provider=self.info.name, url=resp.url)],
            )
        ]


PROVIDER = Acme
```

2. Verify:

```bash
deniz plugins list
deniz providers check acme
deniz run acme alice --type username
```

## Rules

- One `PROVIDER` class per file. `info.name` must match the intended name and
  must not shadow a built-in provider.
- `run()` returns observations or raises a typed error from
  `deniz.kit.errors`. Never print.
- Observations need at least one `Source`. Set confidence honestly.
- Declare `auth`, `cost` and a conservative `rate`; the HTTP client enforces
  the rate per host.
- Do not read files or environment variables directly; use `ctx.auth`.

## Distribution

Expose an entry point so `pip install` is enough:

```toml
[project.entry-points."deniz.providers"]
acme = "acme_deniz:Acme"
```

Entry points are validated the same way as directory plugins. Errors are
shown by `deniz plugins list` and never stop startup.

## Limits

- No sandbox: a plugin can do anything the process can.
- Declare `API_VERSION = CONTRACT_VERSION`; see `docs/compatibility.md`. A
  mismatch is rejected at load with a visible plugin error.
- `ctx.max_items` and `ctx.max_workers` are the only budget helpers.
