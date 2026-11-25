# Contributor container

Open the repository in a devcontainer (VS Code: *Reopen in Container*) and the
dependencies plus pre-commit hooks install themselves.

First 15 minutes:

```bash
python -m pytest -q tests/test_models.py
python -m pytest -q -m "not load" tests/test_scaffold.py
python -m deniz new-provider my_source --title "My source" --root /workspace
python -m pytest -q tests/test_my_source.py
```

Remove the generated files if you only wanted a dry run. The generator also
adds the provider to `BUILTIN`; review that diff before committing.

The full gate is in `CONTRIBUTING.md`. Load tests are excluded by default:

```bash
python -m pytest -q -m "not load"
python -m pytest -q -m load
```

The container has no provider credentials. Copy `providers.toml.example` and
set environment names, or run keyless providers only.
