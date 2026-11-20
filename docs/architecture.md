# Architecture: actors and actions

*Kind: explanation.* What is in the system, who acts on it, and what they do. The design reasons are in [explanation-design.md](explanation-design.md); the interfaces in [reference-api.md](reference-api.md).

## Actors

| Actor | What it is |
|---|---|
| Application | The program that links the library and owns the socket. It calls the engine and does all I/O and time-outs. |
| Peer | The other end of the connection (a TLS client or server). Untrusted: every byte it sends is input to a parser. |
| Network | Carries the bytes between the two. Untrusted; can read, change, drop, replay, reorder and inject. |
| Certificate authority | Signs the peer's certificate; trusted through the trust anchors that the application gives. |
| Operator / maintainer | Builds and releases the library; has no part at run time. |

## Components and actions

```
 Application
   | 1 set up: profile function, versions, suites, trust anchors, key, buffer
   | 2 push/pull bytes (br_ssl_engine_* or br_sslio_*)
   v
 SSL engine  (src/ssl/ssl_engine.c)  one connection = one context, no heap
   | 3 records: split, protect, check (ssl_rec_*.c TLS 1.0-1.2; ssl_rec13_*.c TLS 1.3)
   | 4 handshake: a state machine written in T0 (ssl_hs_client/server/common.t0)
   |      -> hello, key exchange, certificate, signature, Finished, tickets, KeyUpdate
   | 5 key schedule: HKDF (ssl_tls13_ks.c), helpers (ssl_tls13_hs.c)
   | 6 certificate validation: X.509 engine (src/x509) against trust anchors
   | 7 server policy: chooses the certificate and signs (ssl_scert_*.c); client
   |      certificate handler (ssl_ccert_*.c)
   | 8 session cache: remembers sessions and TLS 1.3 tickets (server) (ssl_lru.c)
   v
 Primitives (src/hash, src/symcipher, src/aead, src/ec, src/rsa, src/mac, src/kdf, src/rand)
   constant-time code; no heap; no system calls
```

1. The application chooses what is allowed. Defaults stop at TLS 1.2; TLS 1.3 is switched on by the application.
2. The engine is a state machine: the application reads the engine's outgoing bytes and gives it incoming bytes; the engine never calls `read` or `write`.
3. Every record from the peer goes through length checks and decryption before anything is parsed.
4. The handshake parser reads each message into fixed buffers or hashes it on the fly; a message above a fixed limit is refused (`BR_ERR_LIMIT_EXCEEDED`).
5. Secrets (traffic secrets, resumption secrets) live in the engine context, which the application owns; the library does not copy them elsewhere.
6. A certificate chain is validated as it is received, with a fixed amount of memory.
7. For TLS 1.3 the policy handler is asked for the certificate and signature scheme (`choose13`) and for the signature (`do_sign13`).
8. TLS 1.3 session tickets are identifiers into the server's session cache.

## Build and release actors

The maintainer pushes through a pull request; GitHub Actions builds and tests; a tag starts the release workflow, which makes the source archive, the SBOM and the signatures ([releasing.md](releasing.md)). No actor has a long-lived secret.
