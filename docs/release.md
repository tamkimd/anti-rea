# Release Anti-REA with GitHub Actions

This release flow runs from GitHub Actions. It tests the selected `main` commit, builds the Python wheel and source distribution, publishes them to PyPI with Trusted Publishing, and creates a GitHub Release with the same files and checksums. It does not read a local `.env` file or copy a PyPI token to GitHub.

## One-time setup

Anti-REA is registered on PyPI. In [PyPI project settings](https://pypi.org/manage/project/anti-rea/settings/publishing/), add a GitHub Trusted Publisher with:

| Setting | Value |
|---|---|
| Owner | `tamkimd` |
| Repository | `anti-rea` |
| Workflow filename | `release.yml` |
| GitHub environment | `pypi` |

The workflow grants OIDC permission only to its PyPI publishing job. PyPI uses this publisher identity to issue a short-lived upload credential; no long-lived API token is required in GitHub secrets. See [PyPI's setup instructions](https://docs.pypi.org/trusted-publishers/adding-a-publisher/) and [security model](https://docs.pypi.org/trusted-publishers/security-model/).

## Publish a new version

1. Set the new `MAJOR.MINOR.PATCH` version in `pyproject.toml` and commit the release changes to `main`.
2. In GitHub, open **Actions → Release → Run workflow**, select `main`, and run it.
3. The workflow verifies the selected commit is still the latest `main`, runs unit tests and Ruff, builds and checks the distributions, and smoke-tests the built wheel.
4. On success, it creates the `v<version>` tag, publishes the wheel and source distribution to PyPI, then creates a GitHub Release with those files and `SHA256SUMS`.

The workflow reads the version from `pyproject.toml`; it rejects reused or older versions and tags that point to another commit. Re-running the same workflow can resume an interrupted release while the selected commit is still the latest `main`: existing PyPI and GitHub files are accepted only when their SHA-256 hashes match the tested artifacts. If `main` has moved, update the release commit and start a new run. Fix a failed run before starting another version.

Run the Actions workflow only after the version change is committed to `main`. The GitHub release job uses the same artifacts built and tested earlier in the run; it does not rebuild them.

## Optional detached manifest signature

The `anti-rea release-manifest` commands create and verify an additional manifest for a wheel. This signature is separate from PyPI publishing and does not sign an application that Anti-REA analyzes. The repository has no configured trusted Ed25519 release key, so the workflow does not claim or attach a signed manifest. Do not treat an unsigned manifest or an untrusted signing key as release authentication.
