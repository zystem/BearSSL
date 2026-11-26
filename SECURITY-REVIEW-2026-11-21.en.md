# BearSSL-tls13 expert assessment

21 November 2026 · reviewed revision `9f8cded` · Linux x86-64

**Verdict.** For an existing application built on BearSSL, the fork deserves further work. I would postpone deploying this revision as a general-purpose TLS 1.3 server. The main reasons are a missing mandatory X25519 check and an insufficient binding of resumable sessions to the authentication policy. Basic interoperability is good. All 45 scenarios with OpenSSL, GnuTLS and Go passed, including mTLS, HelloRetryRequest and session resumption.

The review was done on a clean build from `git archive`. The main attention went to the new TLS 1.3 logic, the boundaries between it and the BearSSL primitives, and the properties that the tests actually check. Conclusions drawn from the code are kept apart from the results of test runs. The review did not cover all of upstream BearSSL.

## What to fix first

### 1. High priority — X25519

The shared client and server code checks the return code of `mul` and then passes the result to the key schedule. For example, the default i31 backend returns 1 after encoding the coordinate, without checking the result for zero. TLS 1.3 requires aborting the handshake when the shared secret is all zeros. This is a violation of a mandatory check, confirmed from the code. A bypass of certificate authentication was not established during the review. [ECDH handling](src/ssl/ssl_tls13_hs.c) · [i31 backend](src/ec/ec_c25519_i31.c) · [RFC 8446 §7.4.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.4.2)

**Fix.** Check every byte of the X25519 result in a fixed number of operations, in the shared TLS layer, before HKDF. Pin the same behavior for client and server across all supported backends.

### 2. High priority with a shared cache or a change of mTLS policy — authentication context

The built-in server cache stores the identifier, the secret, the version and the cipher suite. After a successful binder check the server sets `tls13_authed` and skips the client certificate exchange. If the cache has outlived a tightening of the policy, or serves configurations with different requirements, an entry alone does not confirm that the client went through the mTLS that is required today. With separate caches and an unchanged policy the risk is much lower. [Built-in LRU](src/ssl/ssl_lru.c) · [PSK acceptance and certificate request](src/ssl/ssl_hs_server.t0)

**Fix.** Separate the caches by trust domain and reset them when the policy changes. Store the policy version and the result of the original authentication in the entry. If the application needs the identity of the client, keep the verified identity, or require a full handshake.

### 3. Medium priority — ticket lifetime

The client stores `ticket_lifetime`, but when it prepares a PSK it checks only the ticket length, the version and the cipher suite. Only `ticket_age_add` is written into `obfuscated_ticket_age`, so the reported age is zero. The built-in server LRU does not store an expiry time either. This lengthens the window in which saved credentials can be reused, even with 0-RTT off. [PSK preparation](src/ssl/ssl_tls13_hs.c) · [ClientHello construction](src/ssl/ssl_hs_client.t0) · [RFC 8446 §4.6.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.6.1)

**Fix.** Let the application supply a monotonic time, compute the age on the client and enforce the lifetime on both sides. Limit the life of a ticket to seven days and add tests of the expiry boundary with a controllable clock.

### 4. Medium priority for long-lived connections — key rotation

The fork answers the peer's KeyUpdate, and the GCM counter grows with every record. For AES-GCM, the key usage limit that the RFC recommends is reached well before the 64-bit counter overflows. This matters most for gRPC connections that stay open all the time. [GCM counter](src/ssl/ssl_rec13_gcm.c) · [KeyUpdate behavior](docs/supported-versions.md) · [RFC 8446 §5.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.5)

**Fix.** Introduce a threshold on the sending key for each AEAD. Initiate KeyUpdate before the threshold is reached, and close the connection if the key cannot be changed safely. Test the transition with an artificially small test threshold.

### 5. Medium priority for RFC conformance — length of the protected record

Both decoders accept an outer length of up to 16384 + 256 and only then check the length of the content, already without the padding and the type. The RFC limits the whole TLSInnerPlaintext, type and padding included, to 16385. The buffer-capacity and tag checks solve other problems. No sign of a write beyond the buffer was found on this path. [AES-GCM](src/ssl/ssl_rec13_gcm.c) · [ChaCha20-Poly1305](src/ssl/ssl_rec13_chapol.c) · [RFC 8446 §5.4](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.4)

**Fix.** Check the length of the whole inner plaintext before the padding is removed, and take the negotiated record_size_limit into account. Put the shared check in one place and test both sides of the boundary for both codecs.

## Leaks and constant time

**The wipe of the PSK disappears under optimization.** In br_ssl_server_tls13_psk_lookup a temporary structure holds the PSK. The source ends the successful path with `memset(&tmp, 0, sizeof tmp)`. In the machine code of the default GCC 13.3 build, after the PSK is copied the function goes straight to the epilogue without zeroing the temporary structure. A copy of the PSK may stay on the stack. Exposing it needs additional access to the process memory, for example through a dump. Introduce a portable function that guarantees the wipe, and use it on the error paths as well. Separately, define when the handshake traffic secrets and the master secret are wiped after their last use. [Handling of key material](src/ssl/ssl_tls13_hs.c)

**Comparison of TLS 1.3 Finished.** In the examined GCC build the compiler produced an XOR/OR loop whose iteration count follows the public length, with no exit at the first mismatch. A similar pattern is visible in the sources of the binder check and of the AEAD tags. Removing the padding takes time that depends on its length. Production code checks the tag before the loop runs. The observation concerns a possible leak of the hidden length of an authenticated message. There is no evidence here of remote recovery of a key or of content. If the threat model includes hiding the length, measure records of equal outer length with different padding on the target processor. Statistical timing measurements were not part of the review. [Finished and binder](src/ssl/ssl_tls13_hs.c) · [Tag and padding](src/ssl/ssl_rec13_gcm.c)

**Bounds of the public HKDF API.** br_tls13_expand_label uses fixed stack buffers and relies on the documented limits of the algorithm, the label and the output length. The built-in engine passes known labels. For an external C client, a violation of the precondition can lead to a memory-safety error. Add a checked function that returns an error. Passing the prefix and the label to HMAC in separate calls would remove the 255-byte temporary buffer. [API contract](inc/bearssl_tls13.h) · [Implementation](src/ssl/ssl_tls13_ks.c)

## Tests that were run

The logs below are kept in a temporary directory on the machine where the check was run. If the report is moved or /tmp is cleaned, these links may stop working.

| Check | Result |
|---|---|
| GCC 13.3, clean build, testcrypto all, testx509, style_check.sh | Exit code 0. The X.509 log has 53 OK lines. The testcrypto all set skips hardware backends that are not available. [Cryptographic tests](/tmp/bear-review.Tlse9V/crypto.log) · [X.509](/tmp/bear-review.Tlse9V/x509.log) |
| Clang 18, ASan + UBSan + LeakSanitizer | All six TLS 1.3 groups and X.509 passed. UBSan had the alignment and function-type checks disabled. LeakSanitizer passed on a rerun outside the sandbox. Remaining copies of keys on the stack need a separate check. [TLS 1.3](/tmp/bear-review.Tlse9V/san/tls-lsan.log) · [X.509](/tmp/bear-review.Tlse9V/san/x509.log) |
| BearSSL client with OpenSSL 3.0.13 | 14/14. [Log](/tmp/bear-review.Tlse9V/interop-authorized.log) |
| Bidirectional matrix with OpenSSL, GnuTLS and Go | 31/31 in total. The standard script ran 18 cases with OpenSSL and GnuTLS and returned success after a Go build error from the archive copy. The other 13 Go scenarios passed separately, with the VCS stamp turned off in go build. [OpenSSL and GnuTLS](/tmp/bear-review.Tlse9V/server-authorized.log) · [Go](/tmp/bear-review.Tlse9V/go-review.log) |
| Local benchmark, i9-13900HX, 100 repetitions per configuration | TLS 1.3 AES-128-GCM 1.105 ms, AES-256-GCM 1.110 ms, ChaCha20 1.104 ms, mTLS 1.892 ms. A full handshake and a short exchange were measured in one process. These numbers do not measure AEAD throughput. [Log](/tmp/bear-review.Tlse9V/bench.log) |

## Comparison with the TLS WG projects

The TLS WG list includes endpoint implementations, analyzers, test tools and historical versions of the draft. For example, the rustls line that carries a draft number is a poor basis for judging today's rustls. [TLS WG list](https://github.com/tlswg/tlswg-wiki/blob/main/IMPLEMENTATIONS.md) · [rustls](https://github.com/rustls/rustls)

| Projects | What they mean for choosing and checking BearSSL-tls13 |
|---|---|
| wolfSSL, CycloneSSL | Close alternatives for embedded C. The fork's advantage for an existing BearSSL integration is the familiar handling of buffers and I/O. For a new device, measure Flash, maximum stack and the RAM of a full connection on the specific MCU. wolfSSL also supports RTOSes and hardware accelerators. [wolfSSL](https://www.wolfssl.com/products/wolfssl/) |
| OpenSSL, BoringSSL, GnuTLS, NSS | Independent peers for checking the protocol. OpenSSL and GnuTLS have a wider set of mechanisms, post-handshake authentication among them. The fork was checked in both roles with both. Add BoringSSL and NSS to the matrix next, especially for HRR, tickets and KeyUpdate. |
| picotls, rustls, Fizz | picotls is the reference for compact TLS 1.3 in C, rustls for an integration where Rust is acceptable, Fizz for high-performance C++ and zero-copy. A performance comparison needs the same certificates, CPU, record sizes and resumption policy. The fork's current benchmark gives no such comparison. [picotls](https://github.com/h2o/picotls) · [rustls](https://github.com/rustls/rustls) |
| tlsfuzzer, Wireshark | tlsfuzzer is useful for independent checks of failures and state transitions, Wireshark for analyzing traces. Successful connections with three libraries left the mandatory X25519 check unnoticed. That is a concrete reason to extend the negative tests. |

## Tests, style and optimization

1. **Make an incomplete interop matrix visible in CI.** A go build error is only printed, and the scenarios disappear from the result. For mandatory peers, fail the job; for optional ones, print SKIP; at the end, compare the number of cases that ran. The script also ends processes with pkill -x by name, which is dangerous on a shared machine. Save the PID of each process it starts and end only that one. [Interop script](test/interop_server13.sh)
2. **Measure the coverage of the new TLS 1.3 branches.** The 87.2% the project publishes is line coverage of the whole library, upstream included. For a release, count the C branches and the T0 transitions separately for the full handshake, HRR, PSK, key changes and failures in each role. Keep the parser fuzzing with cryptography disabled, and add checks of a production build in which AEAD, Finished, binder and CertificateVerify are really verified. Long-running fuzzing, ARM, big-endian and a 32-bit architecture were not run as part of this review. [Project report](docs/testing.md)
3. **Correct the capability matrix.** The documentation promises verification of ECDSA P-521 and RSA-PSS/SHA-512, but br_ssl_engine_tls13_verify_cv recognizes only four schemes on SHA-256 and SHA-384. A successful HRR with the P-521 group tests the key exchange. Every claimed scheme needs its own CertificateVerify test with an independent peer. Until then, narrow the documentation to the combinations that are actually supported. [Capability registry](docs/supported-versions.md) · [Signature check](src/ssl/ssl_tls13_hs.c)
4. **Optimize for the real constraint.** On the x86 that was checked, the difference between the three suites in a short handshake was only 0.006 ms. For embedded use, first measure the maximum stack with X.509 and HKDF, the RAM with both I/O buffers, the size of the linked application, and the speed of processing 1 KiB and 16 KiB records on the target ARM. For a server gRPC workload, measure resumption and a long stream with key rotation separately. Fix the benchmark, which can print FAILED and exit with code 0. [Benchmark](test/bench_handshake.c)

**Order of the fixes.** First the X25519 check and the isolation of the resumption policies, then the ticket lifetime, the record limits and the guaranteed wipe of the PSK. Before a production recommendation, these properties should be checked on an ordinary release build in both roles. A skipped mandatory test should stop the release.
