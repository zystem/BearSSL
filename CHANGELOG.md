# Changelog

Changes against upstream BearSSL `7bea48e`. Dates 2026. Versions are `X.Y.Z-tls13.N` ([docs/releasing.md](docs/releasing.md)).

## Unreleased

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
