# TLS 1.3 for BearSSL: fork plan

Status: plan only. No TLS 1.3 code is written yet.
Decision (user, 2026-11-17): fork BearSSL and add TLS 1.3 (client and server, mTLS), instead of a rewrite in Nim/Forth or another library.

## Baseline (run 2026-11-17)

- Upstream: `https://bearssl.org/git/BearSSL`, master `7bea48e` (2026-04-06). Last tag `v0.6`. Upstream is not dead: 5 commits since 2024-01-01, all bug fixes.
- This fork starts from `7bea48e`. Toolchain here: gcc 13.3, Nim 2.4.0, no Mono/.NET.
- `make` builds (about 1 minute). `./build/testx509` and `./build/testcrypto all` pass (exit 0). The TLS engine itself has no unit tests in this tree (`test/` has `test_crypto.c`, `test_math.c`, `test_speed.c`, `test_x509.c` only); the engine is tested upstream with the separate BoarSSL/Twrch framework, which is not in this repository.
- The handshake is in `src/ssl/ssl_hs_{client,server,common}.t0` (about 4170 lines of T0). `T0Comp.exe` needs Mono to regenerate `ssl_hs_*.c`.
- Mono 6.12.0 is installed (2026-11-17, by the owner). `make T0` runs `mono T0Comp.exe` on all seven `.t0` sources and the regenerated C is byte-identical to the committed C (`git status` shows only `TLS13-PLAN.md`). So the T0 toolchain is reproducible here.

## What exists and what is missing (checked in the 0.3.1 nimble copy, 2026-11-17)

Present: HKDF (`src/kdf/hkdf.c`), X25519, P-256/384/521, ECDSA, AES-GCM, ChaCha20-Poly1305 record codecs, SHA-256/384, HMAC, RSA-PSS verification, minimal X.509 validator.
Missing: any TLS 1.3 state, RSA-PSS signing, Ed25519, tickets/PSK, a record codec with the 1.3 inner content type.

## Design decisions

1. **The handshake is written in T0** (owner's decision, 2026-11-17), in the same files as 1.2, in the style of the code that is there. The generated `ssl_hs_*.c` is committed with every change to a `.t0` file (as upstream does), so users do not need Mono. Plain C is used only for what T0 does badly: the key schedule and record codecs are C words called from T0 with `cc:` (as the existing PRF and record switching are). Parts that stay C: `src/ssl/ssl_tls13_ks.c` (HKDF-Expand-Label, secrets), `ssl_rec_*13.c` (record codecs).
   - How the 1.2 T0 code is laid out (read 2026-11-17): `do-handshake` in `ssl_hs_client.t0` is a straight sequence (`write-ClientHello`, `read-ServerHello`, certificate, key exchange, CCS/Finished); `main` waits for renegotiation with `wait-co`. Common words (`read-handshake-header`, `read8/16/24`, `open-elt/close-elt`, `write-*`, `multihash-init`, `switch-encryption`, `read-Certificate`, `process-alerts`) are in `ssl_hs_common.t0` (136 words).
   - A 1.3 flow is a second word, `do-handshake13`, next to `do-handshake`. `read-ServerHello` is the fork: it reads `supported_versions` and the HelloRetryRequest random, and either continues the 1.2 path or returns a flag for the 1.3 path. Renegotiation does not exist in 1.3, so `main` for a 1.3 connection never reaches the `wait-co` renegotiation branch (KeyUpdate is handled there instead).
   - Risk: `process-alerts` and the record-type handling in `ssl_hs_common.t0` assume plaintext handshake records until CCS; in 1.3 handshake records are encrypted with the inner type inside, and CCS records are ignored (compatibility mode). This part of the common code must change carefully, with the 1.2 test results unchanged.
2. **Reuse the engine's buffers, I/O and record vtable** (`br_sslrec_in_class`, `br_sslrec_out_class` in `inc/bearssl_ssl.h`). Answered in step 2: the 1.3 codecs have their own vtables (`br_sslrec13_in_class`, `br_sslrec13_out_class` in `inc/bearssl_tls13.h`); `decrypt` returns the inner type through an output argument and takes no record type or version (the caller checks that the outer type is 23). The engine, which holds one `br_sslrec_in_class` pointer today, will need a second pointer or a tagged union for 1.3 when it is wired in (step 3).
3. **No malloc, fixed buffers**, as in the rest of BearSSL. Handshake messages in 1.3 (certificate chains) can be larger than one record; they must be reassembled in the engine's input buffer or hashed on the fly.
4. **First version without**: PSK/tickets/resumption, 0-RTT, Ed25519, post-handshake client auth, KeyUpdate sent by us (KeyUpdate received is handled). Added later if needed.
5. **Cipher suites**: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`. Groups: X25519, secp256r1. Signatures: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256 (verify first, sign for servers with RSA keys).
6. **Naming and API**: new `BR_TLS13`; `br_ssl_engine_set_versions` accepts it; existing 1.2 users are unaffected unless they raise `version_max`.

## Steps, each with a gate

| # | Step | Gate |
|---|------|------|
| 0 | Fork baseline builds and its tests pass | done 2026-11-17 |
| 1 | Key schedule (HKDF-Expand-Label, secrets, transcript hash) as a standalone module | passes the RFC 8448 simple-handshake key values. **Done 2026-11-17** for SHA-256 (`testcrypto TLS13_KS`: early, handshake and master secrets, handshake and application traffic secrets, keys, IVs, Finished keys, KeyUpdate in-place check; vectors generated from the RFC text). SHA-384 is not covered: RFC 8448 has no trace for it |
| 2 | 1.3 record codecs (AES-GCM, ChaCha20-Poly1305: nonce from counter, inner type, padding) | encrypt/decrypt vectors from RFC 8448; round trip; bad-tag and bad-length tests. **Done 2026-11-17** (`testcrypto TLS13_REC`): AES-128-GCM against all 7 encrypted records of the RFC 8448 simple trace (4 key/sequence series); AES-256-GCM and ChaCha20-Poly1305 against records made with the independent Python `cryptography` package (RFC 8448 has no vectors for them), after checking that Python construction against every RFC record; 16384-byte record by SHA-256; padded record, all-zero (no inner type), flipped bit in data and tag, out-of-order sequence, length limits, `max_plaintext`. AddressSanitizer + UBSan (alignment check off) run 2026-11-18 on `testcrypto TLS13_KS`, `TLS13_REC`, `HKDF`: clean, exit 0 (`vm.mmap_rnd_bits` was 28, read by the owner with sudo). The alignment check was not run (upstream's deliberate unaligned load in `br_dec32le`). |
| 3 | Client handshake: ClientHello with key_share, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished | full RFC 8448 trace replayed with fixed randomness; interop with OpenSSL `s_server -tls1_3` |
| 4 | HelloRetryRequest; downgrade protection | tests against OpenSSL with an unsupported first group |
| 5 | Server handshake, mTLS (CertificateRequest, client Certificate) | interop: OpenSSL and Go clients; Go server with client auth |
| 6 | RSA-PSS signing; ALPN, SNI | h2 ALPN with the gRPC stack |
| 7 | Fuzzing of the handshake parser; ASan run (check `vm.mmap_rnd_bits` first, see CLAUDE.md) | 24 h fuzz clean; ASan clean |
| 8 | Nim package fork with the patch; `TlsConfig` switch in nim-grpc and CiNim | existing nim-grpc `ttls` tests and the CiNim soak pass |
| 9 | Documentation (README try-it, reference, changelog, "not independently audited") | try-it commands run in a test |

### Step 3 in parts (started 2026-11-18, branch `tls13-client-hs`)

| Part | Content | State |
|------|---------|-------|
| 3a | Engine hooks: per-direction 1.3 codec (`tls13_in`, `tls13_out`, `in_enc`), inner type becomes `record_type_in`, plaintext CCS accepted while input is protected, `br_ssl_engine_switch13()` | **Done 2026-11-18** (7e75e18). Checked: build without warnings; `brssl client` and `brssl server` against OpenSSL 3.0.13 with TLS 1.2 work; `testx509`, `testcrypto all` pass. Not checked: nothing sets the 1.3 flags yet, so the new paths have not run |
| 3b | Engine state for 1.3 (key share, secrets, transcript snapshot) and C helpers for the T0 code (`ssl_tls13_hs.c`: keygen, hs_keys, snapshot, finished, check_finished, app_keys, switch) | **Done 2026-11-18**. `testcrypto TLS13_HS`, vectors from RFC 8448 (parsed, not typed): both handshake and both application traffic secrets, server and client Finished, decryption of the real 679-byte server flight through `br_ssl_engine_switch13`, encryption of the client Finished and an application record. Mutants (swapped label argument, disabled Finished comparison) fail the test. ASan+UBSan (alignment off) clean on TLS13_HS/KS/REC; `brssl client` 1.2 against OpenSSL still works; `testcrypto all`, `testx509` pass. Not run: the helpers have not been called from T0; P-256 share and SHA-384 suites have no test vector; the RFC X25519 scalar is little-endian and must be reversed for the BearSSL API (random keys are unaffected) |
| 3c | T0: ClientHello extensions (supported_versions, key_share, signature_algorithms incl. rsa_pss_rsae_sha256/384), `read-ServerHello` fork, 1.3 suite table entries, plaintext CCS ignored in 1.3 mode, `brssl` names for `-vmax tls13` and the three suites | **Done 2026-11-18** (branch `tls13-client-hello`). Checked against OpenSSL 3.0.13 `s_server` (TLS 1.3): it accepts the ClientHello; the client parses the ServerHello, derives the handshake keys and decrypts the first protected record (EncryptedExtensions) for all three suites, which also checks the SHA-384 key schedule against OpenSSL (open item of step 1). `do-handshake13` is still an interim stub that stops with `BR_ERR_BAD_STATE` after that. A 1.3-capable client against a 1.2-only server completes TLS 1.2; `brssl client`/`server` in 1.2 still work; `testcrypto all`, `testx509` pass. T0 return stack of the client went 27 -> 32 entries (new locals), so `rp_stack` in the engine is now 48. Not run: ASan on the brssl interop; downgrade-sentinel rejection (no server to produce it); P-256 key share against a peer; HelloRetryRequest is rejected with `BR_ERR_UNSUPPORTED_VERSION`. A server tool with `-vmax tls13` is not supported (server code unchanged; 1.3 suites are filtered out of its 1.2 negotiation). Offering TLS 1.3 clears the cached session ID (no 1.2 resumption when `version_max` is TLS 1.3) |
| 3d | T0: EncryptedExtensions, Certificate (1.3 format), CertificateVerify (ECDSA P-256/SHA-256, P-384/SHA-384, RSA-PSS SHA-256/384), server and client Finished, application keys, NewSessionTicket ignored, KeyUpdate received and answered | **Done 2026-11-18** (branch `tls13-client-flight`). `brssl client -vmax tls13` completes the handshake and transfers data with `openssl s_server` 3.0.13: `sh test/interop_openssl13.sh` (7 cases: ECDSA P-256 with the three suites, ECDSA P-384, RSA-PSS with SHA-256 and SHA-384 suites, ALPN h2; each fetches a 200 KB file and compares it). Also run by hand: 300 KB transfer, KeyUpdate requested by the server (we answer with ours; both directions decrypt afterwards), untrusted certificate is refused (`BR_ERR_X509_NOT_TRUSTED`). ASan+UBSan (alignment off) on `brssl` for four of these runs: no reports. Mutant check: a wrong CertificateVerify context string fails the handshake with `BR_ERR_BAD_SIGNATURE`. Not run at handshake level: a server that sends a wrong Finished or a bad signature (only the Finished comparison is covered by the unit test `TLS13_HS`); Go or any non-OpenSSL peer; CertificateRequest (client authentication) is refused with `BR_ERR_NO_CLIENT_AUTH` (step 5); the client does not send KeyUpdate on its own; HelloRetryRequest (step 4). `br_ssl_engine_set_default_rsavrfy()` now also installs the RSA-PSS verifier (`irsapssvrfy`), which adds that code to every build that uses it |
| 3e | Gate: RFC 8448 trace replay with fixed randomness; `brssl client` against `openssl s_server -tls1_3` | **Done 2026-11-18** (branch `tls13-rfc8448-replay`). `testcrypto TLS13_REPLAY` runs the whole client engine against the RFC 8448 simple trace: the RFC client key share is installed and the RFC ClientHello replaces ours in the transcript (ours has other extensions, so it cannot match byte for byte); the RFC ServerHello and the 679-byte encrypted server flight (EncryptedExtensions, RSA-PSS CertificateVerify signed by the RFC key, Finished) are accepted; our client Finished record equals the RFC record byte for byte; the NewSessionTicket is ignored; our application-data record equals the RFC one and the server's is decrypted. The server key comes from the RFC certificate through a known-key X.509 context (validity and trust not tested there). Mutants (CertificateVerify context, application secret swap, Finished hash length) fail it with errors 27, (ticket decrypt) and 24. ASan+UBSan (alignment off) clean on the four TLS13 tests. Done together: the client now offers and honours `record_size_limit` (RFC 8449) with TLS 1.3, because the RFC server sends it in EncryptedExtensions and an unoffered extension must be refused |

Notes found while reading the code (2026-11-18):
- The engine's multi-hasher already hashes handshake bytes by `record_type_in`/`record_type_out` == 22, and the inner type becomes `record_type_in` after decryption, so it can serve as the TLS 1.3 transcript; snapshots are taken with `br_multihash_out()` before reading CertificateVerify and Finished.
- Certificate in 1.3 has a request context and per-entry extensions, so `read-Certificate` (common code) needs a 1.3 variant.
- CertificateVerify needs RSA-PSS verification; the engine only has the PKCS#1 verifier pointer today (`irsavrfy`).
- The suite table in `ssl_hs_common.t0` has no 1.3 entries; `suite-supported?` rejects them now.
- Careful: a Python `str.replace` that does not match is silent; one engine edit was lost that way and showed up only as a 1.2 interop failure. Check each edit with `git diff`.

Rough effort (estimate, not measured): client only, steps 1-3: 6-8 weeks. Whole plan to step 8: 3-5 months.

## Risks

- No independent audit of the new code; say so in the README. The existing primitives keep their constant-time design; the new code is protocol logic (transcript, nonce, downgrade, Finished checks), where the test vectors and `tlsfuzzer` are the main defence.
- Upstream is slow; the fork must merge its security fixes by hand. Keep our changes in new files and small hooks to keep merges easy.
- Public API changes affect `nim-bearssl`; keep struct layouts compatible where possible and version the fork.
- Security-relevant behaviour that must not regress: certificate validation in `x509_minimal` stays the same for 1.2.

## Decisions needed from the owner

1. Where the fork lives (GitHub repository name; this directory is `~/github/BearSSL-tls13`, a local clone without a remote).
2. Client first, or client and server together from the start.
3. (Answered 2026-11-17: Mono is installed, work is in T0.)

## Open technical question about T0

T0 has a fixed data stack and return stack (printed by T0Comp: for example `main: ds=17 rs=27` for the X.509 decoder), and no recursion. The 1.3 handshake needs more parsing state (`key_share`, `supported_versions`, `signature_algorithms`, certificate extensions per entry). The first T0 step must check the stack depths T0Comp reports for the new words and keep them small, as the 1.2 code does.
