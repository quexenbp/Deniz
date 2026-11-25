# Versioning decision

## Current line

`0.1.0` is the first Deniz release: package, module and command `deniz`.

## Version reset

The 3.0.0bN betas are retired. Reasons for publishing the rewrite as `0.1.0`:

- The product and package are new; `0.x` honestly signals API movement.
- Carrying `3.x` into the new package makes migration comparisons noisy.
- The reset happens once, at release, not twice.

## Rules

- `0.x`: minor may break; patch is fixes only. Changelog marks every break.
- From `1.0`: semver. Contract bumps (`CONTRACT_VERSION`) are major.
- Schema changes follow the envelope rules in `docs/compatibility.md`.
- The version lives in `pyproject.toml` and `deniz/kit/__init__.py`; both move
  together. `deniz version` reads the module.
- Pre-releases use `aN`/`bN`/`rcN` and are not installed by default ranges.

## Checks before any upload

```bash
bash scripts/publish-check.sh      # Windows: .\scripts\publish-check.ps1
```

TestPyPI first, then PyPI. CI uses Trusted Publishing (OIDC, no token); local
uploads need a free API token in `TWINE_USERNAME`/`TWINE_PASSWORD`. See
`docs/publishing.md`.
