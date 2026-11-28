# Roadmap

*Kind: explanation.* What the maintainer intends to do in the next twelve months (from 2026-11-20), in order. These are intentions, not promises: the project has one maintainer ([GOVERNANCE.md](../GOVERNANCE.md)) and no funding, and a security fix goes before everything here.

## Next

1. **Run a 24 hour fuzz on the code of each release** with `test/fuzz/run.sh`; the changes of 2026-11-28 have none yet ([testing.md](testing.md)).
2. **Move the Nim package** (`nim-bearssl`) to this fork, so that nim-grpc and CiNim build against it without patches ([contrib/nim](../contrib/nim/README.md)). This is the reason the fork exists.
3. **Watch the weekly runs** (`fuzz.yml`, `scorecard.yml`, CodeQL) and fix what they find before anything else is added.
4. **Merge upstream** when it changes (the fork tracks `v0.6` plus the commits after it); keep the TLS 1.3 code in separate files so the merge stays small ([explanation-design.md](explanation-design.md)).

## Later, if there is a need and a reviewer

- A second maintainer is invited (2026-11-20, write access, pending); admin access and the rights over the settings stay with the owner ([GOVERNANCE.md](../GOVERNANCE.md)).
- An independent review of the TLS 1.3 handshake. Without it the status in [explanation-security-status.md](explanation-security-status.md) does not change.
- Timing measurements of the new protocol code ([threat-model.md](threat-model.md), "Not covered").
- Tickets that survive a server restart, and a check of ticket age.

## Not planned

0-RTT (early data), Ed25519 and Ed448 certificates, post-handshake client authentication, a compiled release, and a stable binary interface: see [supported-versions.md](supported-versions.md) for why.
