# API changes against upstream BearSSL

*Kind: reference.* Everything that this fork added or changed in the public headers. Upstream functions that are not listed behave as before. Doxygen comments in [`inc/bearssl_ssl.h`](../inc/bearssl_ssl.h) and [`inc/bearssl_tls13.h`](../inc/bearssl_tls13.h) are the long form.

## Constants

| Name | Value | Meaning |
|---|---|---|
| `BR_TLS13` | `0x0304` | Protocol version for `br_ssl_engine_set_versions()` and `session.version`. |
| `BR_TLS13_AES_128_GCM_SHA256` | `0x1301` | TLS 1.3 suite. Uses SHA-256. |
| `BR_TLS13_AES_256_GCM_SHA384` | `0x1302` | TLS 1.3 suite. Uses SHA-384. |
| `BR_TLS13_CHACHA20_POLY1305_SHA256` | `0x1303` | TLS 1.3 suite. Uses SHA-256. |
| `BR_TLS13_MAX_TICKET` | `512` | Largest ticket a client keeps, in bytes. A larger one is ignored: no resumption, no error. |

The TLS 1.3 suites are in no profile: add them to the list of `br_ssl_engine_set_suites()` (default: none, TLS 1.3 is off). Other limits that are compiled in: a HelloRetryRequest and the ServerHello copy kept for it, 400 bytes (larger: `BR_ERR_LIMIT_EXCEEDED`); a cookie, 255 bytes; a CertificateRequest context, 255 bytes.

## Engine

| Item | Change | Default and notes |
|---|---|---|
| `br_ssl_engine_set_versions(cc, min, max)` | accepts `BR_TLS13` | Profiles keep `max = BR_TLS12`. Needs the call before `*_reset()`. |
| `br_ssl_engine_set_rsapssvrfy()` | new | The RSA-PSS verifier. `br_ssl_engine_set_default_rsavrfy()` sets it. If you set only `br_ssl_engine_set_rsavrfy()`, the client does not offer RSA-PSS, and RSA certificates cannot be used with TLS 1.3. |
| `br_ssl_engine_tls13_resumed(cc)` | new | Non-zero if this connection was resumed with a ticket. |
| `br_ssl_engine_tls13_ticket_count(cc)` | new | Number of tickets sent (server) or received (client) on this connection. |
| `br_ssl_engine_context` | grew by 1584 bytes | 3616 to 5200 bytes; the client context 3720 to 5304. Rebuild everything that includes the header. |
| `br_ssl_engine_context.rp_stack` | 32 to 48 entries | The handshake code needs a deeper return stack. |

The record size limit extension (RFC 8449) is offered and honoured with TLS 1.3 without a setting.

## Session parameters (`br_ssl_session_parameters`)

New fields: `ticket_len`, `ticket_age_add`, `ticket_lifetime`, `ticket[BR_TLS13_MAX_TICKET]`. With TLS 1.3, `master_secret` holds the resumption secret (as long as the hash of the suite) and `session_id` is not used by the client; a server's ticket is a 32-byte identifier in `session_id`. `br_ssl_client_forget_session()` also clears `ticket_len`. The structure is larger: code that stores it (a file, a database) must be rebuilt, and stored values from before the change are not valid.

## Server policy handlers (`br_ssl_server_policy_class`)

| Method | Meaning |
|---|---|
| `choose13(pctx, cc, sig_algs, choices)` | Choose a certificate and signature scheme. Returns 1 on success. `sig_algs` has bit `8 + h` for ECDSA and `16 + h` for RSA-PSS (`h` is the hash id: 4 = SHA-256, 5 = SHA-384, 6 = SHA-512). |
| `do_sign13(pctx, hf, rng, hv, hv_len, sig, sig_len)` | Sign the CertificateVerify hash. Returns the signature length, 0 on error. |

A `NULL` method means the handler cannot be used with TLS 1.3; the server does not fall back to another handler. `br_ssl_server_set_single_rsa()` and `br_ssl_server_set_single_ec()` have both. The RSA ones need an RSA-PSS signer: `br_ssl_server_set_single_rsa()` takes it from `br_rsa_pss_sign_get_default()`.

## Client certificate handlers (`br_ssl_client_certificate_class`)

Same two methods (`choose13` with the `br_ssl_client_certificate` result, `do_sign13` with a hash id). `NULL` `choose13`: no TLS 1.3 client authentication; the client answers a request with an empty Certificate. `br_ssl_client_set_single_rsa()` and `br_ssl_client_set_single_ec()` have them.

## Key schedule (`inc/bearssl_tls13.h`)

`br_tls13_ks_init()`, `br_tls13_ks_advance()`, `br_tls13_expand_label()`, `br_tls13_derive_secret()`, `br_tls13_traffic_keys()`, `br_tls13_finished_key()`, `br_tls13_next_traffic_secret()`: HKDF-based key schedule (RFC 8446, section 7.1) for SHA-256 and SHA-384, and the record codec vtables `br_sslrec13_*`. The engine uses them; programs normally do not. A hash other than SHA-256 or SHA-384 is not checked and gives an undefined result.

## Not changed

TLS 1.2 behaviour, the X.509 engine, the primitives, the I/O wrapper. The TLS 1.2 handshake CPU time is the same as upstream (1.334 ms against 1.334 ms, 2026-11-20, see [testing](testing.md)).
