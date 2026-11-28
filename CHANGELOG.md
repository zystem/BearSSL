# Changelog

Changes against upstream BearSSL `7bea48e`. Dates 2026. Versions are `X.Y.Z-tls13.N` ([docs/releasing.md](docs/releasing.md)).

## Unreleased

### Fixed (2026-11-28, found with tlsfuzzer: [docs/conformance.md](docs/conformance.md))
- TLS 1.3: a ChangeCipherSpec after the peer's handshake, or a protected one, is refused (`unexpected_message`); it was ignored.
- TLS 1.3: the version of an unprotected record is ignored. A peer that sent ChangeCipherSpec right after its ClientHello, with the version of that record, was refused with `protocol_version`.
- A server answers an empty list of signature algorithms with `decode_error`.
- `br_ssl_engine_hs_reset()` clears the TLS 1.3 role mark of the connection before.

### Changed (2026-11-28): TLS 1.0 and 1.1 are off by default
- `br_ssl_client_init_full()`, `br_ssl_server_init_full_rsa()` and `br_ssl_server_init_full_ec()` set a minimum of TLS 1.2 (before, TLS 1.0, as upstream; RFC 8996 deprecates 1.0 and 1.1). A program that needs an older peer calls `br_ssl_engine_set_versions()` ([docs/upgrading.md](docs/upgrading.md)).
- `brssl client`, `server` and `twrch` have `-vmin TLS-1.2` as the default; scripts that talk to older peers add `-vmin TLS-1.0`, also when they give only `-vmax`.

### Changed (2026-11-28): requirements of RFC 9846 and RFC 8446 that were not met ([docs/rfc9846.md](docs/rfc9846.md))
- TLS 1.3: an alert of level warning ends the connection like a fatal one; `user_canceled` is ignored at either level. A peer that sends warnings it expects to be ignored is now cut off.
- Both roles refuse a message after a Finished in the same record, and the client one after a ServerHello (`unexpected_message`); the first was accepted before.
- A server refuses a TLS 1.3 ClientHello with a `legacy_version` other than 0x0303, or without `supported_groups`, `signature_algorithms`, `key_share` or `psk_key_exchange_modes` where they are required; some of these were accepted before. Compression is `illegal_parameter`.
- A client refuses an extension of TLS 1.2 in a TLS 1.3 ServerHello, which it accepted before.

### Changed (2026-11-27): TLS 1.3 errors are told to the peer
- In both roles a TLS 1.3 connection that fails because of what the peer sent now sends a fatal alert (before, most failures closed the transport in silence). The error is set while the state is still `BR_SSL_SENDREC`; the engine is closed once the alert has been taken ([docs/reference-api.md](docs/reference-api.md), "Alerts on errors"). A program that treats a set error as "closed" keeps working and sends no alert. TLS 1.2 and older are not changed. The context has four more bytes of state: rebuild dependent code.
- A server and a client now refuse (`unexpected_message`) application data in the middle of a message sent after the handshake, and data after a KeyUpdate in the same record (RFC 8446 section 5.1); both were accepted before.

### Fixed (2026-11-22, the reassessment of that day: [docs/conformance.md](docs/conformance.md))
- A server refuses a ticket at exactly 7 days, like a client; `br_ssl_engine_set_tls13_clock_required()` skips tickets when there is no clock; `test/resume_client.c` sets the clock.
- The SHA-256 of the client's certificate is kept with a TLS 1.3 session (`br_ssl_engine_tls13_client_cert_hash()`), so a program that needs the identity of the client has it after a resumption.
- `br_ssl_session_cache_lru_forget()` overwrites the secret of the entry; new `br_ssl_session_cache_lru_wipe()`.
- One exit that wipes the shared secret on every path of the handshake-key function.
- The interop script keeps the logs of a failed case and waits for a port to listen.
- Tests: the seed generator of the fuzz targets works again (broken since `0.6.1-tls13.1`: it read secrets that the engine had wiped), and CI runs it on each pull request.

### Changed (needs a rebuild of dependent code)
- `br_ssl_session_parameters` has `cert_hash`; `br_ssl_engine_context` has the clock flag, the hash of the client certificate and a SHA-256 context; the entries of `br_ssl_session_cache_lru` are 144 bytes (112 before): size the cache again.

## 0.6.1-tls13.1 — 2026-11-22

Security and conformance fixes found with tlsfuzzer, with other TLS implementations as peers, in their closed issues and in the review of 2026-11-21 (all in [docs/conformance.md](docs/conformance.md)). **Upgrade from `0.6.1-tls13.0`**: that release accepts an X25519 key share of small order (an all-zero shared secret, RFC 8446 section 7.4.2), resumes a session under another client-authentication policy, and has no limit of records for one key. No CVE was assigned: there was no report from outside the project. This release needs a **rebuild of everything that includes the headers** (the structures grew, the cache entries are 112 bytes). Still not independently audited. The 24 hour fuzz run of this code (192.168.100.4, 8 workers per target, started 2026-11-21 16:03) was **not finished** when this release was made; the 24 hour runs of the earlier code and a 10 minute run of this code found nothing ([docs/testing.md](docs/testing.md)). The tag of this release is the first one that is signed. *Correction of 2026-11-26: those two runs were of commit `0fa53ee`, which does not have the last change of this release (`8af7ae2`, wiping of secrets), and the seed generator of the fuzz targets does not work in this release.*

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
