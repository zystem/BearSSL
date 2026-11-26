# Threat model

*Kind: explanation.* What the library protects, against whom, how, and what it does not protect against. State on 2026-11-20. **Not independently reviewed**: this is the maintainer's own assessment.

## What is protected

- Confidentiality and integrity of the application data of a connection, and authentication of the peer, as TLS 1.0 to 1.3 provide them.
- Private keys, traffic secrets and resumption secrets in memory (as far as a C library can: see "Not covered").
- The availability of the application against a malformed message: no crash, no unbounded memory use.

## Who attacks

| Attacker | Can | Cannot |
|---|---|---|
| Network (active) | read, change, drop, replay, inject, downgrade attempts | forge a record or a Finished without the keys; make us accept a lower version without the downgrade sentinel being caught |
| Malicious peer | send any byte sequence; a valid-looking certificate chain; large or deeply nested messages | write beyond a buffer (bounds are explicit); exhaust memory (there is no heap; buffers are fixed) |
| Malicious or compromised CA | issue a certificate for any name | be trusted unless the application has put it in the trust anchors |
| Co-located process / timing observer | measure time, cache effects | (design goal) learn secrets from timing: the primitives are constant-time; the new protocol code does not branch on secrets by design, **not measured** |
| Supply chain | change the source in a pull request, a dependency, a workflow or a release | (design goal) get a change in without the checks; the library has no third-party dependencies; releases are signed and attested ([security-policies.md](security-policies.md)) |

## Attack surface

The code that parses bytes from the network, in order of exposure:

1. **Record layer** (`ssl_rec_*.c`, `ssl_rec13_*.c`): length fields, padding, inner content type, tag check. Constant-time tag comparison.
2. **ClientHello / ServerHello and extensions** (`ssl_hs_server.t0`, `ssl_hs_client.t0`): `supported_versions`, `key_share`, `supported_groups`, `signature_algorithms`, `psk_key_exchange_modes`, `pre_shared_key`, cookie, ALPN, SNI, `record_size_limit`. Each is read with a length limit; unknown extensions are skipped.
3. **HelloRetryRequest and the transcript restart**: a fixed copy buffer (400 bytes); a larger message is refused.
4. **Certificate messages and X.509 parsing** (`src/x509`): chains are validated while they stream in, with a fixed state.
5. **Signatures**: ECDSA and RSA-PSS verification, constant-time big-integer code (upstream).
6. **Tickets and PSK**: the server looks a 32-byte identifier up in its cache; the binder is checked in constant time; a wrong PSK ends the connection with `decrypt_error`.
7. **Post-handshake messages**: KeyUpdate and NewSessionTicket.
8. **Configuration by the application**: wrong use (a policy handler without `choose13`, no seeded PRNG) is the application's responsibility; the documents say what is needed ([reference-api.md](reference-api.md)).

## Mitigations in place

- No `malloc`; fixed buffers with explicit bounds; no recursion in the handshake (T0).
- Strict state machine: a message at the wrong time is an error (`BR_ERR_UNEXPECTED`).
- Downgrade protection: the `DOWNGRD` sentinel is set by the server and checked by the client.
- Tests: RFC 8448 vectors, interoperability with OpenSSL, GnuTLS and Go, AddressSanitizer and UndefinedBehaviorSanitizer on the unit and interoperability tests, libFuzzer targets for the client and server with seeds ([testing.md](testing.md)). CodeQL runs on pull requests.
- Mutation checks of the key schedule labels (a wrong label is caught only by independent peers; that is why they are run).

## Not covered, or not known

- **No independent audit** of the TLS 1.3 code.
- **Side channels** of the new code were reviewed by us, not measured; no timing tests.
- **Replay of session tickets**: the server does not mark a ticket used; with a clock (`br_ssl_engine_set_tls13_time()`) it refuses a session older than 7 days, without one a ticket lives as long as the cache keeps it. There is no 0-RTT, so replay does not reach early data. A session is bound to the server's policy identifier and, for a server that asks for client certificates, to client authentication.
- **Revocation** (CRL, OCSP): not done by BearSSL.
- **Fault attacks, memory disclosure by the application, a compromised host**: out of scope.
- **Wiping of secrets**: the temporary copies in the TLS 1.3 code are wiped with `br_tls13_wipe()`, which the optimiser may not remove (the object code was inspected for one function, see [conformance.md](conformance.md)); the handshake secrets, the PSK and the key exchange values go when the handshake is over, and everything (application secrets, resumption secret, keys of the record codecs) when the engine fails or is closed. What the application copies out (a saved session) is the application's. Memory that the engine used for TLS 1.2 and the application data in the buffers are not wiped.
- **A hostile build environment** (compiler or the Mono toolchain) is out of scope; generated handshake code is committed and checked against the T0 sources in CI.
- The finished 24 hour fuzz runs found nothing, the last one in commit `0fa53ee` (2026-11-21 to 22). The code released as `v0.6.1-tls13.1` and the later fixes of 2026-11-22 have no finished fuzz run; one was started on 2026-11-26 ([testing.md](testing.md)).

## Attack surface changes

A new message parser, a new extension, a new certificate type or a new API that takes network data changes this list: update it in the same pull request ([CONTRIBUTING.md](../CONTRIBUTING.md)).
