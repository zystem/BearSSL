# Security status

*Kind: explanation.*

## Not audited

**No one outside this project has reviewed or audited the TLS 1.3 code.** It is protocol logic that was written in 2026 (transcript handling, key schedule use, Finished and CertificateVerify checks, HelloRetryRequest, tickets). The primitives (AES, ChaCha20, Poly1305, SHA-2, HKDF through HMAC, EC, RSA) are upstream's and keep upstream's constant-time design; upstream has been read by many more people than this fork.

## What was done instead

- Test vectors: the key schedule and record protection against RFC 8448; the client handshake replayed against RFC 8448's trace, including the HelloRetryRequest trace.
- Interop: OpenSSL, GnuTLS, Go, grpc-go, nim-grpc, both roles, with mutual TLS, HelloRetryRequest, KeyUpdate and resumption.
- Mutation checks: wrong labels and wrong contexts were put in on purpose to see that a test fails.
- Sanitizers: AddressSanitizer and UndefinedBehaviorSanitizer (the alignment check off) on the unit tests and the interop runs.
- Fuzzing: libFuzzer on the client and server engines with a build in which the cryptographic checks are off (so the fuzzer reaches the parser). A 24-hour run was in progress on 2026-11-20; its result is not in these documents yet ([testing](testing.md)).

## What is known to be missing

- No ticket age check or replay protection beyond the server cache; no 0-RTT (so replay does not matter for early data, which does not exist).
- No `tlsfuzzer` run, no other conformance suite.
- No timing or cache-leak measurement of the new C code. The new code handles secrets only through the upstream HMAC and AEAD code and compares MACs and tags in constant time by design; this was reviewed by us, not measured.
- Alignment sanitizer not run (upstream deliberately loads unaligned words).
- Interop was run on Linux x86-64 only.

## Reporting a problem

Open an issue on https://github.com/zystem/BearSSL. For a security problem, do not put the details in the issue: say that you have one and ask for a private way to send it (there is no `SECURITY.md` and no private reporting channel set up yet). Problems in code that this fork did not change belong to upstream.
