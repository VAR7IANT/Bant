# Releasing Bant (maintainers)

Clients that have `bant self-update` look at GitHub Releases. Publishing a release is all it takes for them to see the update.

1. **Version.** Edit `__version__` in `bant/__init__.py` (semantic versioning). Move the `[Unreleased]` notes in `CHANGELOG.md` under the
   new version and date. The release tag **must** be `v<version>`: the release workflow refuses a mismatch.
2. **Check.** `ruff check bant tests && pytest`, and wait for CI on `main`. Run the relevant items of the real-VPS checklist in
   [TESTING.md](TESTING.md) before calling a release stable.
3. **Tag and publish.** Create the release on GitHub for tag `v<version>` (target `main`). Tick **Set as a pre-release** while Bant is
   still unproven on real servers (the default `auto` update channel includes pre-releases below 1.0.0).
4. **Assets (automatic).** On `release: published`, `.github/workflows/release.yml` builds `bant-<version>.tar.gz` (`git archive`, top directory
   `Bant-<version>/`) and `SHA256SUMS` and uploads both. `bant self-update` prefers these and verifies the checksum; without them it falls back
   to the tag's source archive and checks the embedded commit against the tag.
5. **Verify.** On a test server running the previous version: `sudo bant self-update check`, then `sudo bant self-update`, then
   `bant version`. `sudo bant self-update rollback` must return to the old version.

Notes
- Do not move or delete a published tag; clients cache the last check result and a rewritten tag would fail their commit check.
- A release whose `install.sh` is broken is rejected by `bash -n` before anything is touched; one that installs the wrong version is
  rolled back automatically by the updater. Neither is a substitute for testing.
- Versions older than the first one containing `self-update` cannot update themselves; their users run `git pull && sudo bash install.sh` once.
