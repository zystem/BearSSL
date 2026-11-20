# Security policies of the project

*Kind: reference.* The rules the project holds itself to; the automatic parts are in [`.github/workflows/`](../.github/workflows/).

## Findings in dependencies and licenses (software composition analysis)

The library has no third-party dependencies ([building.md](building.md)); the dependencies of the project are the GitHub Actions of the workflows and the tools the tests call. Tools: Dependabot alerts and security updates, Dependency Review on every pull request, the software bill of materials of every release.

Threshold for remediation of a finding about a vulnerability in a dependency:

| Severity (CVSS) | A fix exists | No fix exists |
|---|---|---|
| Critical, High | fixed before the next release, and at once if the vulnerable code is reachable from our workflows or our released files | recorded with the reason it is not exploitable; a mitigation is applied if it is reachable |
| Medium | within 30 days | recorded |
| Low | at the next routine update | none |

Licenses: the repository is MIT. A dependency must be under a permissive license (MIT, BSD, Apache-2.0, ISC, MPL-2.0); Dependency Review accepts only an allowed list (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, 0BSD, Unlicense, CC0-1.0, BlueOak-1.0.0, MIT-0, CC-BY-4.0) and refuses the rest, in particular copyleft (GPL, AGPL).

**Before a release**: the CI of the tagged commit must be green (build, tests, sanitizers, CodeQL results read), and no Critical or High finding with a fix may be open. A finding that is accepted instead of fixed is written into the changelog with the reason ([releasing.md](releasing.md)).

**Automatic gate**: Dependency Review runs on every pull request and fails it on a known vulnerability of High or Critical severity or on a denied license. It is a required check of the ruleset on `master` ([GOVERNANCE.md](../GOVERNANCE.md)). The malicious-package and vulnerability alerts of Dependabot are on.

## Vulnerabilities that do not affect the project (VEX)

A finding of a scanner in a component that a release contains or is built with, that does not affect the released source, is either fixed or **accounted for** in the OpenVEX document [`vex/bearssl-tls13.openvex.json`](../vex/bearssl-tls13.openvex.json): for each such vulnerability, the products (releases) and a status (`not_affected` with a justification and an impact statement saying why, or `fixed`). The file is attached, signed, to each release. Today it has no statements: no such finding exists; it is updated before a release when a scanner reports one.

## Findings of static analysis (SAST)

Tools: CodeQL for C on every pull request and weekly, the warnings of gcc and clang (`-W -Wall -Werror`), AddressSanitizer and UndefinedBehaviorSanitizer on the unit tests.

Threshold: a finding of any severity is fixed before the change is merged, or dismissed in the CodeQL alert with the reason written there (false positive, used in tests only). The CI fails on a compiler warning or a sanitizer finding. A finding that appears in CodeQL after the merge is fixed within 14 days for High and Critical, and 30 days for the rest. The result is read before a release.

## Dynamic analysis

The unit tests run under AddressSanitizer and UndefinedBehaviorSanitizer in CI. The fuzz targets in `test/fuzz` run weekly for a short time in CI (`fuzz.yml`), and for 24 hours before a release when the code of the handshake changed since the last long run; a finding is a bug, fixed before the release, with a test or a seed that reproduces it.

## Secrets and credentials

- No secret is in the repository (`.gitleaks.toml` is the configuration for `gitleaks` run by the maintainer; GitHub secret scanning and push protection are on).
- The library holds no secret of the project. Private keys of users are the application's; the test certificates and keys in `samples/` and `test/` are test data and protect nothing.
- The CI uses no long-lived secret: the release uses the short-lived `GITHUB_TOKEN` of the run and the identity of the workflow for signing. A new secret in the CI needs a reason in the pull request and is a repository secret limited to the job that needs it.
- Rotation: a secret that could have been seen is replaced at once, and removed from where it was; there are none to rotate on a schedule. The maintainer's account has two-factor authentication (GitHub requires it); the signing key of a tag is an SSH key kept in an agent, replaced if the machine is lost.
- A secret that leaked is treated as compromised: replaced first, then the logs are read for its use.

## Support of releases

See "What is supported" in [../SECURITY.md](../SECURITY.md).
