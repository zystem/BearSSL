# Making a release

*Kind: how-to.* For the maintainer ([GOVERNANCE.md](../GOVERNANCE.md)). A release is a tag `vX.Y.Z` on `master`; the workflow [`release.yml`](../.github/workflows/release.yml) does the rest: the tests again (`ci.yml`), the source archive, the SBOM and the VEX document, the keyless signatures, the build provenance, and the GitHub release. Nothing needs a secret: the workflow uses the short-lived token of the run. The first release, `v0.6.1-tls13.0`, was made with these steps on 2026-11-20 and `v0.6.1-tls13.1` on 2026-11-22 (the first with a signed tag): the workflow passed on its first run each time (CI, then `release`), and the assets were verified as in [verifying-releases.md](verifying-releases.md).

## Version numbers

Upstream BearSSL's tags `v0.4` to `v0.6` are upstream's. This fork's versions are `vX.Y.Z-tls13.N`: `X.Y.Z` is the upstream release it is based on, `N` counts the fork's releases on it (the first is `v0.6.1-tls13.0`, since the fork is based on upstream after `v0.6`). A version is never reused and a tag is never moved ([verifying-releases.md](verifying-releases.md)).

## Before

1. `master` is green (the checks of the last run on it), the 24 h fuzz result of the current handshake code is written in [testing.md](testing.md) and has no finding (if it is not finished, the release notes say so), no Critical or High finding with a fix is open ([security-policies.md](security-policies.md)), and nothing is open that must go in.
2. Read what went in since the last tag (`git log vPREV..master --oneline`).

## The release pull request

3. A branch `release-X.Y.Z-tls13.N`. In `CHANGELOG.md` the heading `## Unreleased` becomes `## X.Y.Z-tls13.N — DATE`, with the user-visible changes and the security fixes (with their identifiers) added. If a scanner has reported a finding in something a release contains since the last release, account for it in `vex/bearssl-tls13.openvex.json` (raise `version`, set `timestamp`).
4. In [supported-versions.md](supported-versions.md): the new release is the latest; the previous one gets its end date (30 days from this release, see SECURITY.md).
5. Commit with a sign-off (`git commit -s`), push, open the pull request, wait for the checks, merge.

## The tag

6. `git checkout master && git pull`, then `git tag -s vX.Y.Z-tls13.N -m "vX.Y.Z-tls13.N"` (a signed annotated tag; the repository setting is `gpg.format ssh`, `user.signingkey` the path of your public key, then `git tag -v` to check it as in [verifying-releases.md](verifying-releases.md)) and `git push origin vX.Y.Z-tls13.N`. The tag starts the workflow `Release`.
7. Wait for it (`gh run watch`). It runs `ci.yml` first and publishes only if that passes.

## After

8. Check what was made, as a user would ([verifying-releases.md](verifying-releases.md)): the assets, `sha256sum -c`, `cosign verify-blob` of each file, `gh attestation verify` of the archive. Write the result with the date into verifying-releases.md.
9. If something is wrong with a release, do not move the tag: fix on `master` and make the next release; say what was wrong in its notes.
