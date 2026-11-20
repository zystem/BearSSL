# Security policy

This library protects network connections, so a report of a weakness is welcome and is read first. **The TLS 1.3 code of this fork has not been independently audited** ([docs/explanation-security-status.md](docs/explanation-security-status.md)).

## Reporting

- Use GitHub's private vulnerability reporting for this repository (Security → Report a vulnerability). It reaches the maintainer only.
- Do not put details of an unfixed problem into a public issue.
- Say what you saw, on which commit, and how to see it again; a failing test, a packet capture or a fuzz input is the best report.
- A weakness in code that comes from upstream BearSSL and that this fork did not change is also a report for upstream ([bearssl.org](https://www.bearssl.org/)); say so in the report, and we pass it on and fix it here.

## Coordinated disclosure, and the timeframe

- **Acknowledgement** within 7 days of a report; an assessment (confirmed, not reproducible, not a vulnerability) within 14 days.
- **Fix**: a confirmed problem is fixed and tested first; for High and Critical severity the target is a release within 30 days, for the rest the next release. The reporter is told when the fix is ready.
- **Disclosure**: after the fix is released, or after 90 days from the report if no fix is possible, whichever is first (earlier by agreement). The problem is then described in [CHANGELOG.md](CHANGELOG.md) and in a GitHub security advisory, with the people who reported it named if they wish. The data about found vulnerabilities is public there.
- **Contact**: the private vulnerability reporting of this repository is the security contact. The project has one maintainer ([GOVERNANCE.md](GOVERNANCE.md)); if a report is not acknowledged within 7 days, open a **public issue that holds no details** ("security contact request") and it will be answered with a private way to send the report.

## What is supported

- **Scope**: the latest release (all fixes of security problems are made there) and the head of `master`. An earlier release does not get a fix: update to the latest.
- **Duration**: a release is supported until the next release is made; the previous release is supported for 30 days after the new one, for fixes of High and Critical problems only. The fork is young (first release in 2026) and has no long-term-support line.
- **End of support**: when a release is no longer supported it is said in the release notes of the release that replaces it. A release that is older than 30 days after its successor receives no security updates.
- How a release is verified: [docs/verifying-releases.md](docs/verifying-releases.md). The policies for dependencies, analysis and secrets: [docs/security-policies.md](docs/security-policies.md). How the project is run: [GOVERNANCE.md](GOVERNANCE.md).

The threat model is in [docs/threat-model.md](docs/threat-model.md).

## Vulnerabilities in components that do not affect the project

The library has no dependencies besides the C library and, to rebuild the generated handshake, Mono (not shipped). A finding in a component of a release's build or test tooling that does not affect the released source is stated in the OpenVEX document that is attached to each release (see [docs/security-policies.md](docs/security-policies.md)).

## What helps a reviewer

- [docs/threat-model.md](docs/threat-model.md), [docs/architecture.md](docs/architecture.md), [TLS13-PLAN.md](TLS13-PLAN.md) (the plan and what was run in each step).
- Tests are the specification: `build/testcrypto all`, the interop scripts in `test/`, the fuzz targets in `test/fuzz`.
- Scanners that the project runs: CodeQL, gitleaks, Dependency Review, the compilers' warnings, AddressSanitizer and UndefinedBehaviorSanitizer.
