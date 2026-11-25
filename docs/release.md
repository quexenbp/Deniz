# Release

1. Bump `version` in `pyproject.toml` and `deniz/kit/__init__.py`; add a
   `CHANGELOG.md` entry.
2. Run `bash scripts/release-check.sh`.
3. Dry-run the artifact: `bash scripts/publish-check.sh` (or the `.ps1`).
4. Publish to TestPyPI from Actions → release → target `testpypi`, then install
   it in a clean environment (see `docs/publishing.md`).
5. Tag `v<version>` and push. The `release` workflow rebuilds, tests, signs
   with Sigstore, generates SBOM/attestations and publishes to PyPI through
   Trusted Publishing. The tag must match `deniz.__version__`.
6. Verify signatures:
7. Keep the SBOM and bundles on the GitHub release page. No API token is stored
   in the repository.

```bash
cosign verify-blob --bundle dist/<file>.sigstore.json \
  --certificate-identity-regexp 'https://github.com/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  dist/<file>
```

9. Publish `dist/*` to PyPI (`twine upload`). Keep the SBOM and bundles on the
   GitHub release page. Remove the install-from-TestPyPI environment afterward.

The fork is GPL-3.0-or-later. Keep `NOTICE`, `LICENSE` and the SPDX headers.
