# Verifying a release

*Kind: how-to.* **Not run yet: there is no release of this fork when this page was written (2026-11-20). The commands below follow the release workflow and will be run on the first release; the result is then written here.**

Every release (a tag `v*`) is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) on a GitHub-hosted runner, never by hand. The files, the SBOM, the VEX document and their signatures are produced in that one run. Verify before you use: a release that fails any of these checks must not be used; report it as in [SECURITY.md](../SECURITY.md).

The assets of release `vX.Y.Z` (https://github.com/zystem/BearSSL/releases): `bearssl-tls13-X.Y.Z.tar.gz` (the source tree at the tag, made by `git archive`), `bearssl-tls13-X.Y.Z.tar.gz.sha256`, `bearssl-tls13.spdx.json` (the software bill of materials, SPDX), `bearssl-tls13.openvex.json` (the VEX document, [security-policies.md](security-policies.md)), and a `.sigstore.json` bundle for each of the four files. There are no compiled assets: the library is built from source ([building.md](building.md)).

## Integrity (the content is what was built)

```bash
sha256sum -c bearssl-tls13-X.Y.Z.tar.gz.sha256
```

## Authenticity and identity (who built it: this repository's release workflow)

The signature is keyless (sigstore): the certificate names the workflow that signed, and a public log records it. The expected identity is the release workflow of `zystem/BearSSL` on a tag `v*`; the expected issuer is GitHub Actions.

```bash
cosign verify-blob \
  --bundle bearssl-tls13-X.Y.Z.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/zystem/BearSSL/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  bearssl-tls13-X.Y.Z.tar.gz
```

The same for the SBOM and the VEX document with their own bundles. The archive also has a build provenance attestation:

```bash
gh attestation verify bearssl-tls13-X.Y.Z.tar.gz -R zystem/BearSSL
```

If the identity is anything but the release workflow of this repository on a `v*` tag, the file was not made by this project.

## The tag

Tags are annotated. They are **not signed** yet; the authenticity of a release rests on the signatures of its files above, not on the tag. The source in the archive is the tree at the tag: compare it with `git archive vX.Y.Z` of a clone.
