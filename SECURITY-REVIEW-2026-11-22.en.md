# BearSSL-tls13 security reassessment

22 November 2026 · commit `1740f68f3d3b18a110a4e5241d4e7bbb21a698c0` · Linux x86-64

**Decision.** Keep this MIT-licensed fork as the leading candidate for the size-constrained BearSSL integration. The release addresses the most consequential findings in the previous review. For a deployment that relies on mutual TLS, enable resumption only once the application can enforce expiry, isolate trust policies and recover the authenticated client identity it needs. Full handshakes are a practical interim configuration. Final selection still needs a linked application size measurement. [License](LICENSE.txt) · [Prior review](SECURITY-REVIEW-2026-11-21.ru.md)

## Changes since the first review

| Previous concern | Evidence in this revision |
|---|---|
| All-zero X25519 result could reach HKDF | Both roles use the common ECDH check. It accumulates every output byte before deciding whether to reject. [Handshake helpers](src/ssl/ssl_tls13_hs.c) |
| Resumption lost authentication context | Server lookup compares the policy identifier and requires a previously authenticated session when client certificates are required. The cache carries the certificate-authenticated flag. Identity and policy configuration remain application responsibilities. [Lookup](src/ssl/ssl_tls13_hs.c) · [Cache format](src/ssl/ssl_lru.c) |
| Record size, padding and key rotation | The codecs bound the protected record length, use a shared full-length inner-type scan, and the engine supports proactive sending-key rotation. The record and key-limit test groups passed. [GCM](src/ssl/ssl_rec13_gcm.c) · [ChaCha20](src/ssl/ssl_rec13_chapol.c) · [Engine](src/ssl/ssl_engine.c) |
| PSK lookup cleanup and HKDF argument handling | Lookup now wipes its temporary session on success and after failed loads or policy checks. A checked HKDF label interface validates inputs. Prefer that interface for new callers and propagate its return value. [Handshake helpers](src/ssl/ssl_tls13_hs.c) · [Key schedule](src/ssl/ssl_tls13_ks.c) |

## Remaining findings and recommended changes

**1. High priority for deployments using resumption — expiry depends on integration.** Client and server enforce age only if the application supplies time. The bundled resumption client omits the setter. The server accepts the exact seven-day boundary while the client rejects a ticket at its lifetime. An old PSK can consequently remain usable beyond the intended policy if its cache entry survives and its holder still possesses the secret. Supply a fresh time before every reset, use a consistent clock domain for persisted sessions and default to a full handshake when trustworthy time is unavailable. Align both expiry comparisons. Acceptance tests should cover missing time, clock discontinuities and the second before, at and after expiry. [Age checks](src/ssl/ssl_tls13_hs.c) · [Integration guide](docs/howto-resumption.md) · [Example](test/resume_client.c)

**2. High priority for shared mTLS deployments — preserve principal and trust scope.** A policy number and an authenticated bit cannot identify an individual certificate holder for application authorization. Use separate caches per trust domain or bind entries to a unique domain and policy generation. Rotate that generation when trust anchors, accepted client identities or server credentials change. If authorization uses certificate identity, restore the verified principal from trusted session state or require a full handshake. Verify that a ticket from one tenant cannot resume in another and that a revoked identity cannot regain access after a policy reload. [Lookup and ticket creation](src/ssl/ssl_tls13_hs.c) · [Resumption guide](docs/howto-resumption.md)

**3. Medium hardening priority — explicit cache invalidation leaves key material in memory.** The built-in LRU stores 48 bytes of master-secret material per entry. Its forget operation disables the entry by clearing the version alone. This blocks future lookups but leaves the bytes in caller-owned storage until reuse. Exposure requires another source of memory visibility, such as a process dump. Wipe the secret field on forget, preserve the tree links, and provide a documented teardown operation for the whole backing store. Verify the field is cleared immediately and that unaffected sessions still load. Apply the same lifecycle rule to exported client session parameters. [LRU save, load and forget](src/ssl/ssl_lru.c)

**4. Lower-priority cleanup defect — one error return skips a local shared-secret wipe.** In the handshake-key helper, failure to obtain the expected transcript hash returns after the ECDH result has been copied into the local point buffer. The normal exit wipes that buffer. This matters on internal failure or misconfiguration and would require additional memory disclosure to expose bytes. Route post-ECDH exits through one cleanup path and inspect release object code for the error path. Keeping cleanup local makes it easier to review when the handshake changes. [Handshake key derivation](src/ssl/ssl_tls13_hs.c)

**5. Protocol diagnostics and test reliability.** The project documents parser failures that close the transport without the prescribed alert and four oversized Finished probes excluded from its gate. Map each supported TLS 1.3 error to the expected alert, include both roles, and record exclusions by case with an owner and expiry. Exercise shared TLS 1.2 parser behavior separately. Keep test-only crypto bypasses out of release artifacts and run authentication-negative tests against the exact release configuration. In the interop harness, preserve per-case peer logs on failure and replace fixed startup sleeps with a readiness signal. [Conformance ledger](docs/conformance.md) · [Interop harness](test/interop_server13.sh)

## Timing, memory and footprint

The reviewed binder comparison accumulates differences across the public digest length. Padding removal scans the authenticated plaintext over the public record length. The wipe primitive uses volatile byte stores. These source properties reduce specific risks. Compiler choice, optimization and the selected AES/GHASH implementation still matter. Inspect the instructions of deployed builds and compare timing distributions at fixed public lengths on each supported CPU. No independent timing experiment or remote side-channel claim forms part of this review. [Binder](src/ssl/ssl_tls13_hs.c) · [Padding and wipe](src/ssl/ssl_tls13_ks.c)

The resource benchmark measured 42,482 bytes for the client context, X.509 context and bidirectional buffers combined, plus an observed handshake stack depth of 11,888 bytes for TLS 1.3 on this host. The unstripped multi-command brssl executable was 465,240 bytes. Benchmark the stripped nimgrpc executable using identical certificates, trust store, TLS roles, cipher suites and linker flags. Report incremental file size, peak RAM per active connection, and latency for full and resumed handshakes. Test software and hardware AES separately before changing cipher preferences. [Benchmark](test/bench_resources.c)

## TLS implementation comparison

The TLS WG inventory covers endpoint libraries, tools and historical drafts. Use it to choose independent peers. For this MIT project, picotls is a reasonable second C implementation to size with the intended crypto backend. OpenSSL and GnuTLS already provide independent interoperability coverage without becoming shipping dependencies. NSS or rustls would add another independent state machine. CycloneSSL is a plausible embedded candidate when a commercial agreement fits the distribution model. Its vendor offers GPLv2 and commercial licensing. No comparable target binary was built for these alternatives, so a numeric size ranking would be speculative. [TLS WG inventory](https://github.com/tlswg/tlswg-wiki/blob/main/IMPLEMENTATIONS.md) · [CycloneSSL licensing](https://www.oryx-embedded.com/products/CycloneSSL) · [picotls](https://github.com/h2o/picotls)

The project tracks RFC 8446. The RFC Editor now identifies RFC 9846 as its successor. Before making an unqualified current-conformance claim, map the supported profile and the negative-test matrix against the successor specification. [RFC Editor status](https://www.rfc-editor.org/info/rfc8446/)

## Verification on the reviewed commit

A fresh git archive supplied the sources and test fixtures. The release-style build used the default C flags including -Os. Test counts below are observed in this review.

- Default build and testcrypto all passed, including the ten TLS 1.3 groups. X.509 reported 53 OK results. Architecture-specific availability follows the host.
- Clang 18 ASan and UBSan passed the ten TLS 1.3 groups and X.509. Alignment and function-type instrumentation were disabled. These tests cover only exercised paths.
- The repository style check passed in the Git working tree. Executable documentation checks passed all 232 checks with local sockets enabled.
- BearSSL client to OpenSSL passed 14/14. Peer versions for interop were OpenSSL 3.0.13, GnuTLS 3.8.3 and Go 1.24.2.
- The full bidirectional matrix ran all 46 required cases and exited 1. It passed 43. The three failures were GnuTLS client with RSA-PSS mTLS and Go client with P-256 or P-384 against the BearSSL server. A focused rerun on another loopback port passed all three and two controls. The first run overlapped other tests. The first failing peer logs were discarded by the harness, so the cause remains unresolved. Require a clean full run on an isolated runner before release.
- A separate LeakSanitizer run of the ten TLS groups completed with no leak report. This detects certain unreachable allocations. Retained secrets in live cache storage and stack remnants require explicit lifetime tests.

This review sampled the fork-specific TLS 1.3 paths and assessed changes since commit 9f8cded. Full upstream primitive verification, independent long-running fuzzing, cross-architecture execution and downstream ABI compatibility were outside the measured scope. Rebuild downstream bindings against the current headers, particularly where contexts or session parameters are allocated by value.
