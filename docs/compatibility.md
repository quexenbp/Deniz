# Compatibility

## Provider contract

`deniz.kit.providers.base.CONTRACT_VERSION` is the provider plugin API. A
provider class may declare `API_VERSION`; the registry rejects a mismatch with
a visible plugin error instead of loading it.

| Core | Contract | Python | Status |
|---|---|---|---|
| 0.1.x | 1 | 3.11–3.13 | current |
| 3.0.0bN | 1 | 3.11–3.13 | retired rewrite betas |
| 2.x legacy | — | 3.8–3.12 | upstream |

Rules:

- Contract bumps are major-version changes. A core may support the previous
  contract for one minor release with a deprecation warning.
- Additive fields on `ProviderInfo`/`Context` are minor changes.
- Removing or renaming `Provider.run`, `ProviderInfo` fields or error classes
  is a contract bump.
- Built-in providers and plugins follow the same validator.

## Python

Supported interpreters are declared in `pyproject.toml` and tested in CI:
3.11, 3.12, 3.13. Dropping one is a minor-version note in the changelog.

## CLI and schema

- The `deniz.result/1` envelope is versioned in the schema string.
  Additive fields do not bump it; removal or type change does.
- CLI flags may gain aliases; removing one needs a changelog note and one
  release of overlap.
- `--json` shapes are additive; the MCP tools use the same rule.

## Plugins

Entry-point plugins declare their contract with `API_VERSION`. Keep the value
equal to the core's `CONTRACT_VERSION`; the compatibility matrix in the release
notes tells you which core supports which contract.
