# Verifying a release

*Kind: how-to.* **Run once, on 2026-11-20, by the maintainer's assistant on one Linux machine, on release `v0.6.1-tls13.0` (cosign 3.0.2): `sha256sum -c` passed; `cosign verify-blob` passed for the archive, the SBOM (20 packages) and the VEX document; `gh attestation verify` of the archive returned exit code 0; the file list of the archive equals `git archive` of the tag. Not run: the check by anyone else, and a check on another machine. The VEX document has a signature but no attestation.**

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

The first release, `v0.6.1-tls13.0`, has an annotated tag that is **not signed**. From `v0.6.1-tls13.1` on the tag `vX.Y.Z-tls13.N` is an annotated tag signed with an SSH key by the maintainer who made the release ([releasing.md](releasing.md)); a maintainer adds their public key here when they first make a release. The key of `zystem` is:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPp5WWSw0xFjlzPEtln90NY8dc7MUvkun/14yTINPM/
```

(fingerprint `SHA256:lW4afK66UsIcTD4xXiwz2vutEsLvEYqYk+pTx+MuPHo`; it is also on https://github.com/zystem.keys). To check a signed tag:

```bash
echo "10708003+zystem@users.noreply.github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPp5WWSw0xFjlzPEtln90NY8dc7MUvkun/14yTINPM/" > allowed_signers
git -c gpg.ssh.allowedSignersFile=allowed_signers tag -v vX.Y.Z-tls13.N
```

That prints `Good "git" signature for 10708003+zystem@users.noreply.github.com with ED25519 key SHA256:lW4a...`. Signing and checking were run on a throw-away tag on 2026-11-20 and on the tag `v0.6.1-tls13.1` on 2026-11-22 (good signature both times); `v0.6.1-tls13.0` is the only release tag that is not signed. The signatures of the release files do not depend on the tag. The source in the archive is the tree at the tag: compare it with `git archive vX.Y.Z-tls13.N` of a clone.

Run on 2026-11-22 on the release `v0.6.1-tls13.1` (cosign 3.0.2, `gh attestation verify`, the machine of the maintainer): the release workflow passed on the first run; `sha256sum -c` passed; `cosign verify-blob` passed for the archive, the SBOM (20 packages) and the VEX document; `gh attestation verify` of the archive returned exit code 0; the list of files of the archive equals `git archive` of the tag; `git tag -v` of the tag printed a good signature of the key above. Not run: the check by anyone else, and a check on another machine.
