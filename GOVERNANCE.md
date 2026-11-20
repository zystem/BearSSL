# Governance

This fork of BearSSL is run by one maintainer. This file says how it is run, so that a contributor knows what to expect and a user knows what the controls are. One maintainer is a known weakness, written down below.

## Members and roles

| Member | Role | Access to sensitive resources |
|---|---|---|
| `zystem` (the owner of the repository) | maintainer: decides, reviews and merges, makes releases, answers security reports, holds the settings of the repository (rulesets, security settings, Dependabot) and the badge entry | admin of the repository and its settings; write access to the CI (the CI has no long-lived secrets: [docs/security-policies.md](docs/security-policies.md)) |
| contributors | anyone who sends a pull request or an issue | none |

This is the complete list of members with access to sensitive resources; it is changed in this file when a permission is granted or removed. There are no collaborators.

## How the project is run

- **Decisions** are made by the maintainer, in the open: in issues and pull requests, with the reasons in the commit message or in `docs/`.
- **Contributions** come as pull requests and follow [CONTRIBUTING.md](CONTRIBUTING.md).
- **Escalated permissions** (write access to the repository, the right to publish releases, access to the settings) are given only to a person who has contributed accepted changes over time, whose identity is known to the owner, who uses two-factor authentication (GitHub requires it of anyone who contributes code), and who has been reviewed by the owner before the permission is granted. Nobody has them besides the owner.
- **Releases** are made by the release workflow from a tag that the maintainer creates ([docs/releasing.md](docs/releasing.md)); no person holds a signing key of the project (the signature of the files is keyless, bound to the workflow: [docs/verifying-releases.md](docs/verifying-releases.md)).
- **Review of changes**: every change to `master` is a pull request that the automatic gates check (build, tests, sanitizers, CodeQL, dependency review, DCO: [docs/security-policies.md](docs/security-policies.md)). An approval by a person other than the author is **not** enforced: with one active author a required approval would stop every merge, so the checks must pass and nothing more is required.
- **Security reports** go as in [SECURITY.md](SECURITY.md).

## If the maintainer cannot go on

There is no second person who can take over today. The licence (MIT) lets anyone who has a copy carry on, and the CI keeps no secret that a person could lose. A second maintainer, or a move to an organisation with two owners, would remove this single point; it is open work, not a promise.

Upstream BearSSL also has one author, and this fork follows it by hand ([docs/explanation-security-status.md](docs/explanation-security-status.md)).
