# Changelog

Changes against upstream BearSSL `7bea48e`. Dates 2026. Versions are `X.Y.Z-tls13.N` ([docs/releasing.md](docs/releasing.md)).

## Unreleased

### Fixed (2026-11-22, the rest of the review of 2026-11-21: [docs/conformance.md](docs/conformance.md))
- The TLS 1.3 secrets are wiped: the handshake secrets, the master secret, the PSK and the key exchange values when the handshake is over, all secrets and the record keys when the engine fails or is closed.

### Added (tests)
- `TLS13_WIPE`, `TLS13_TAMPER` (a production build refuses a changed record, a wrong Finished, a signature that does not verify); coverage of the TLS 1.3 C files with floors in CI; `test/bench_resources.c` (memory and speed; printed by the CI job `portability`).

### Fixed (2026-11-21, found with tlsfuzzer and the issue trackers of other TLS projects: [docs/conformance.md](docs/conformance.md))
- The server accepted an X25519 key share of small order (all-zero shared secret) and, late, a key share with an invalid point or a wrong length. It now computes and checks the shared secret before its ServerHello and answers `illegal_parameter`; the client checks the zero X25519 secret too.
- After a HelloRetryRequest the server sent its compatibility ChangeCipherSpec after the ServerHello; it follows the HelloRetryRequest now (RFC 8446 appendix D.4).
- A bad or too long Finished, or a wrong message type in the client's flight, is answered with `decrypt_error`, `decode_error` or `unexpected_message`. A TLS 1.3 Handshake or Alert record with no content is an error (`BR_ERR_UNEXPECTED`) and no longer skipped.

- A security review of 2026-11-21 ([docs/conformance.md](docs/conformance.md), "Fixed because of the review"): a TLS 1.3 session is bound to the server's policy identifier and to client authentication; tickets expire with a clock; the engine changes its sending key before the AEAD limit; the inner plaintext of a record is at most 2^14 + 1 bytes; ECDSA P-521 and RSA-PSS with SHA-512 are verified; the secrets of the TLS 1.3 code are wiped in a way the optimiser cannot remove; the padding is removed in constant time; `br_tls13_expand_label_checked()`.

### Changed (needs a rebuild of dependent code)
- `br_ssl_engine_context` grew (6024 bytes now; `tls13_ecdh_done`, the clock, the counters for the key limit, `tls13_cauth`, `tls13_obf_age`); `br_ssl_server_context` has `tls13_policy_id`; `br_ssl_session_parameters` has `ticket_issued`, `issued_valid`, `policy_id`, `cert_authed`.
- The entries of `br_ssl_session_cache_lru` are 112 bytes (100 before): size the cache again.
- New API: `br_ssl_engine_set_tls13_time()`, `br_ssl_engine_set_tls13_key_update_interval()`, `br_ssl_server_set_tls13_policy_id()`, `br_tls13_expand_label_checked()`; new status `BR_ERR_KEY_LIMIT`; `brssl` has `-ku`.
- A server that asks for client certificates no longer resumes a session of a client that did not use one.

### Added (tests)
- `test/tlsfuzzer/run.sh` and the CI job `tlsfuzzer`: scripts of tlsfuzzer against the TLS 1.3 server; the CI job `portability` (aarch64, macOS arm64, x86 32 bit, s390x big-endian in an emulator).

### Changed (tests)
- The X.509 test vectors in `test/x509` are text (a PEM-like block with Base64) instead of binary DER; `test/test_x509.c` decodes them and the test output is identical. No binary file is tracked any more; `test/style_check.sh` fails if one is.

### Added (project)
- `test/coverage.sh` and the CI job `coverage` (line coverage of `src/`, floor 80 %); `test/style_check.sh`; `docs/roadmap.md`, `docs/assurance-case.md`, `docs/upgrading.md`.
- Release tags are signed from the next release on ([docs/verifying-releases.md](docs/verifying-releases.md)).

## 0.6.1-tls13.0 — 2026-11-20

The first release of the fork. Not independently audited ([docs/explanation-security-status.md](docs/explanation-security-status.md)); no known vulnerability was fixed in it (nothing was released before it). The 24 hour fuzz runs of the TLS 1.3 handshake were not finished when it was made; the trial runs so far found nothing ([docs/testing.md](docs/testing.md)).

### Added
- TLS 1.3 client and server (RFC 8446): suites `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`; X25519 and P-256/384/521; ECDSA and RSA-PSS; HelloRetryRequest and cookies; ALPN, SNI, `record_size_limit`; mutual TLS; KeyUpdate received; downgrade protection. (2026-11-17 to 11-19)
- Resumption with session tickets (`psk_dhe_ke`), tickets are entries of the server's session cache. (2026-11-20)
- `BR_TLS13` and `BR_TLS13_*` suite constants; `br_ssl_engine_set_rsapssvrfy()`; `br_ssl_engine_tls13_resumed()`, `br_ssl_engine_tls13_ticket_count()`; `choose13` and `do_sign13` in the policy and client certificate classes; `inc/bearssl_tls13.h`.
- `brssl` knows `tls13` and the three TLS 1.3 suites.
- Fuzz targets and seeds (`test/fuzz`), handshake benchmark (`test/bench_handshake.c`), interop scripts (`test/interop_*.sh`), Nim patches (`contrib/nim`).
- Documentation (`README.md`, `docs/`).
- Project files, CI and release workflows (`CONTRIBUTING.md`, `SECURITY.md`, `GOVERNANCE.md`, `.github/`, `vex/`); `test/docs_check.sh` and `test/fuzz/mkseeds.sh`.

### Changed (needs a rebuild of dependent code)
- `br_ssl_engine_context` is 1584 bytes larger; `rp_stack` has 48 entries.
- `br_ssl_session_parameters` has four new fields (a ticket of up to 512 bytes).
- `br_ssl_server_policy_class` and `br_ssl_client_certificate_class` have two new methods at the end; the single-RSA client certificate handler now also keeps an RSA-PSS signer.
- `br_ssl_engine_set_default_rsavrfy()` also installs the RSA-PSS verifier.

### Removed
- `T0Comp.exe`, `srv.pid` and the binary fuzz seeds are no longer in the repository (`make T0` builds the compiler; `test/fuzz/mkseeds.sh` makes the seeds).

### Fixed
- A second ClientHello after a HelloRetryRequest that carried `renegotiation_info` was read as a renegotiation (found by the fuzz seed generator; only in the new code).

### Not changed
- TLS 1.0 to 1.2 behaviour and speed.
