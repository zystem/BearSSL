# Upgrading

*Kind: how-to.* How to move to a release of this fork from upstream BearSSL, and from one release of the fork to the next. **Not run with a real program yet**: the steps follow what the structures and the changelog say, and the build and the tests of this repository; no downstream project has been upgraded with them (the first is the Nim package, [roadmap.md](roadmap.md)).

## From upstream BearSSL to this fork

1. Replace your copy of `inc/` and `src/` by the ones of the release (the tag `vX.Y.Z-tls13.N`; check it as in [verifying-releases.md](verifying-releases.md)). The new files `src/ssl/ssl_tls13_*.c` and `src/ssl/ssl_rec13_*.c` must be compiled: if you build with the Makefile of this repository it finds them itself; if you list the files, add them ([building.md](building.md)).
2. **Rebuild everything that includes a BearSSL header, not only the library.** The engine context and the session parameters are larger and two policy classes have two more methods at the end ([../CHANGELOG.md](../CHANGELOG.md), "Changed"). A program built against the old headers and linked with the new library reads the wrong offsets.
3. If your code has its own server policy handler, give it the two new methods (`choose13` and `do_sign13`); a TLS 1.3 handshake stops without them. A client certificate handler of your own with `choose13` set to `NULL` means no client authentication in TLS 1.3 ([reference-api.md](reference-api.md)). TLS 1.2 is not affected.
4. Nothing changes for TLS 1.2 unless you ask: TLS 1.3 is used only when the maximum version is set to it ([howto-enable-tls13.md](howto-enable-tls13.md)).
5. Run your tests; run `build/testcrypto all` and `build/testx509` of the release.

## From one release of the fork to the next

1. Read the section of each release between yours and the new one in [../CHANGELOG.md](../CHANGELOG.md); "Changed (needs a rebuild of dependent code)" tells whether step 2 above applies again.
2. Replace the sources, rebuild all dependent code, run the tests.
3. If you rely on a feature that is listed as not implemented in [supported-versions.md](supported-versions.md), check that page for the new release.

A release is supported until the next is made, and for 30 days after it for fixes of high and critical problems ([../SECURITY.md](../SECURITY.md)). A version is never reused and a tag is never moved.
