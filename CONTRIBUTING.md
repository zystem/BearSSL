# Contributing

This is a fork of [BearSSL](https://www.bearssl.org/) that adds TLS 1.3 ([README.md](README.md)). A change to code that this fork did not touch is better sent to upstream as well.

- **Bugs and ideas**: open an issue. **Security problems**: not in an issue; see [SECURITY.md](SECURITY.md).
- **Build and test**: `make`, then `build/testcrypto all` and `build/testx509`. More: `sh test/docs_check.sh` (the documents), `sh test/interop_openssl13.sh` and `sh test/interop_server13.sh` (interoperability; they need `openssl`, and for the second also `gnutls-bin` and Go), the fuzz targets in [test/fuzz](test/fuzz) (clang with libFuzzer).
- **Coding standard**: the style of the existing code (upstream's): C99, tabs, the function name at the start of a line, no `malloc` in the library, no secret-dependent branch or table index in code that handles secrets, fixed-size buffers with explicit bounds, a comment that says why. The code must compile with `-W -Wall` without a warning, with gcc and with clang: CI builds with `-Werror` and a pull request that does not is not merged. `sh test/style_check.sh` (tabs, no trailing white space, 100 columns) checks the files this fork added; upstream's files are not checked. The handshake is written in T0 (`src/ssl/*.t0`); the generated `ssl_hs_*.c` is committed with every change to a `.t0` file (`make T0`, needs Mono), and CI fails when the committed C differs from what the T0 sources give.
- **Tests**: a change of behaviour comes with a test that fails without it: a unit test in `test/test_crypto.c`, a case in an interop script, or a line in a document that `test/docs_check.py` checks. A parser of input comes with a fuzz target or seeds. A change of a protocol label or a state machine is also checked against an independent peer (OpenSSL, GnuTLS, Go): a test of our client against our server cannot see a wrong label.
- **Documents**: one kind of page, a command with what it prints, what was not run ([docs/README.md](docs/README.md)). A new option, flag, error or setting gets its line in its page in the same change.
- **Cryptography**: no new primitive of our own; use what the library has, and say in the change which RFC the new code follows.
- **Commits**: a short subject saying what changed and why; `CHANGELOG.md` is kept for user-visible changes.
- **Conduct**: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). **Governance and roles**: [GOVERNANCE.md](GOVERNANCE.md).
- **Sign-off (DCO)**: every commit carries a `Signed-off-by: Name <email>` line (`git commit -s`), which says that you have the right to submit the work under the project's license, as in [DCO.md](DCO.md). The `DCO` workflow checks every commit of a pull request (bots are exempt); a commit without the line fails it.
- **License**: by contributing you agree that your work is under the MIT license of the project.

## When and how the tests run

- **By you, before a pull request**: `make`, `build/testcrypto all`, `build/testx509`, `sh test/docs_check.sh`.
- **Automatically**: on every push to `master` and every pull request, [`.github/workflows/ci.yml`](.github/workflows/ci.yml) builds with gcc and clang with `-Werror`, runs `testcrypto`, `testx509`, the document check and the OpenSSL interoperability script, builds with AddressSanitizer and UndefinedBehaviorSanitizer and runs the unit tests again, and compares the generated handshake code with the T0 sources. `codeql.yml` (CodeQL for C) runs on pull requests and weekly, `dependency-review.yml` on pull requests, `scorecard.yml` weekly, and `fuzz.yml` runs the fuzz targets for a short time weekly. A release (a tag `v*`) runs `ci.yml` again before it publishes anything ([docs/releasing.md](docs/releasing.md)).
- **A change of behaviour** (a fix, a feature, a change of a format) adds or updates a test in the automatic suite; a pull request without one is asked to add it.
