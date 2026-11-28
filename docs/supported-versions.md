# Supported versions and features

*Kind: reference.* State on 2026-11-20 (commit of the `tls13-docs` branch, based on `master` 0d4e1a7).

## Protocol versions

| Version | Client | Server | Notes |
|---|---|---|---|
| TLS 1.2 | yes | yes | as upstream; the default |
| TLS 1.0, 1.1 | if asked for | if asked for | deprecated (RFC 8996). The profile functions do not allow them (upstream's full profiles do); `br_ssl_engine_set_versions()` does. `brssl` too: it needs `-vmin TLS-1.0` or `TLS-1.1` |
| TLS 1.3 (RFC 8446; [not all of RFC 9846](rfc9846.md)) | yes | yes | off until the program asks for it |
| SSL 3.0 and older | no | no | as upstream |

## TLS 1.3 features

| Feature | State |
|---|---|
| Cipher suites `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` | yes |
| `TLS_AES_128_CCM_*` suites | no |
| Key exchange groups | X25519 (the first share), then HelloRetryRequest to P-256, P-384 or P-521 (the groups that the EC implementation has) |
| Signatures, verified and made | ECDSA P-256 (SHA-256), P-384 (SHA-384), P-521 (SHA-512) and RSA-PSS `rsae` with SHA-256, SHA-384 and SHA-512, each run against OpenSSL (all roles), GnuTLS and Go (P-521 and PSS-SHA512 as far as their configuration allows) ([conformance.md](conformance.md)). Not Ed25519, not Ed448, not `rsa_pkcs1` in TLS 1.3 |
| HelloRetryRequest, cookie | yes (client and server) |
| Client authentication (mutual TLS) during the handshake | yes |
| Post-handshake client authentication | no |
| ALPN, SNI, `record_size_limit` (RFC 8449), maximum fragment length | yes |
| KeyUpdate | the peer's KeyUpdate is applied and answered; the engine starts one before the limit of the cipher for one key (2^24 records with AES-GCM) |
| Session resumption with tickets and `psk_dhe_ke` | yes, tickets are identifiers in the server's session cache (no stateless tickets). A session is resumed only under the same policy identifier, and, if the server asks for client certificates, only if the client used one. With a clock a ticket lives at most 7 days (`br_ssl_engine_set_tls13_time()`); without one it does not expire by itself |
| `psk_ke` only, external PSK | no |
| 0-RTT (early data) | no |
| Downgrade protection (`DOWNGRD` in the server random) | yes (server sets it, client checks it) |
| TLS 1.2 renegotiation | as upstream; there is none in TLS 1.3 |
| Certificate compression, OCSP stapling, SCT | not processed (ignored if the peer sends them) |

## Tested peers

OpenSSL 3.0.13, GnuTLS (`gnutls-cli`, `gnutls-serv`), Go 1.24 `crypto/tls`, grpc-go 1.75.1 and nim-grpc 0.7.0. Details and what was not run: [testing](testing.md).

## Platforms

Built and run on Linux x86-64 with gcc 13 and clang 18. Not run on other platforms in this fork; upstream's portability remains the goal (the new code uses fixed-size buffers, no heap, no OS calls), but that is not tested here. Not run: 32-bit builds, big-endian, Windows, ARM, bare-metal.

## Releases of this fork

| Release | Based on upstream | State |
|---|---|---|
| `v0.6.1-tls13.1` (2026-11-22) | `7bea48e` | latest, supported ([SECURITY.md](../SECURITY.md)) |
| `v0.6.1-tls13.0` (2026-11-20) | `7bea48e` | supported until 2026-12-22, for fixes of high and critical problems only; **upgrade: it accepts an X25519 key share of small order** |

## Upstream base

Upstream BearSSL commit `7bea48e`. Fixes upstream makes later are merged by hand; there is no promise of how fast.
