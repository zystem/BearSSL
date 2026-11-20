# Building, and where the dependencies come from

*Kind: how-to and reference.*

## Build

Needs a C99 compiler (gcc or clang) and `make`. No other library: BearSSL uses only the C library. On Linux:

```bash
make
```

This builds `build/libbearssl.a`, `build/libbearssl.so`, the tool `build/brssl` and the test programs `build/testcrypto`, `build/testx509` and `build/testspeed`. `make clean` removes `build/`. Other platforms: the files in `conf/` (see the upstream notes in [README.txt](../README.txt)). The compiler flags are in `conf/Unix.mk` (`-W -Wall -Os -fPIC`); CI builds with `-Werror` as well.

Optional, only if you change the handshake: the files `src/ssl/ssl_hs_*.c` are generated from `src/ssl/*.t0` by the T0 compiler (`make T0`), which needs Mono (`mono-devel`, for `mono-csc`). The generated C is committed, so a normal build does not need Mono, and CI checks that the committed C equals what the sources give. `T0Comp.exe` is built by the Makefile and is not stored in the repository.

Tests and checks, each with its prerequisites: [CONTRIBUTING.md](../CONTRIBUTING.md) and [testing.md](testing.md).

## Dependencies: how they are chosen, obtained and tracked

| Dependency | Needed for | How it is chosen and tracked |
|---|---|---|
| a C compiler and `make` | build | any compiler that supports C99; CI builds with gcc and clang of the GitHub runner image |
| the C library | build and run | no BearSSL code beyond `memcpy`, `memset`, `memcmp`, `strlen`; no `malloc` in the library |
| Mono (`mono-devel`) | regenerating the handshake (`make T0`) | not shipped, not needed to build; a maintainer's tool; CI installs the runner's package |
| OpenSSL, GnuTLS, Go | interoperability tests only | not linked; the test scripts call the programs found on the machine; CI uses the runner's packages |
| clang with libFuzzer | fuzzing only | not needed to build |
| GitHub Actions | CI and releases | every action is pinned by commit SHA; Dependabot (`.github/dependabot.yml`) proposes updates weekly; Dependency Review checks each pull request |

The library has **no third-party code** to select or update: the primitives (hashes, AES, ChaCha20, Poly1305, EC, RSA) are part of the repository. New dependencies of the library are not accepted unless there is no alternative; a change that adds one says why in the pull request, and updates this table. Upstream's changes to the code that this fork shares are merged by hand ([explanation-security-status.md](explanation-security-status.md)). There is no package manifest (`go.mod`, `package.json`): the list above is the dependency list.
