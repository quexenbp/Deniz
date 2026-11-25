# Publishing with Trusted Publishing

No API token is stored. GitHub Actions proves its identity to PyPI with OIDC
and uploads through `pypa/gh-action-pypi-publish`.

## Repository remote

The checkout already points `origin` at the Deniz repository:

```bash
git remote -v
# origin   https://github.com/quexenbp/Deniz.git
git push -u origin master
```

## One-time setup on the index

Do this on both <https://test.pypi.org> and <https://pypi.org>.

1. Sign in. PyPI requires 2FA; an authenticator app is free.
2. Open **Publishing** (for a new project) or **Your project → Publishing**.
3. Add a **pending/trusted publisher** with:

| Field | Value |
|---|---|
| PyPI Project Name | `deniz` |
| Owner | `quexenbp` |
| Repository name | `Deniz` |
| Workflow name | `release.yml` |
| Environment name | `testpypi` (TestPyPI) / `pypi` (PyPI) |

The workflow and environment names must match exactly. The package must be
`deniz`; if the name is taken on an index, either rename the distribution or
use a different index.

## GitHub environments

Create two environments in **Settings → Environments**: `testpypi` and `pypi`.
For `pypi`, add required reviewers if you want a manual gate. No secrets are
needed.

## TestPyPI first

Actions → **release** → *Run workflow* → target `testpypi`.

Then install in a clean environment:

```bash
python -m venv /tmp/deniz-test
/tmp/deniz-test/bin/pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  deniz==0.1.0
/tmp/deniz-test/bin/deniz version
```

## PyPI

Push a matching tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The `build` job fails if the tag does not equal `v<deniz.__version__>`. The
`publish-pypi` job then uploads the wheel, sdist and PEP 740 attestations. The
signature bundles and SBOM stay on the GitHub artifact/release page.

Manual fallback: run the workflow with target `pypi` (environment approval
applies). Local token upload remains available:

```bash
TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-... \
  python -m twine upload dist/deniz-0.1.0*
```

## Troubleshooting

- `invalid-publisher`: owner/repo/workflow/environment in the PyPI form do not
  match the workflow run.
- `File already exists`: bump the version; PyPI does not allow overwrites.
- Missing attestations: check the job has `id-token: write` and that
  `attestations: true` is passed.
