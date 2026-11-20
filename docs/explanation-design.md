# Why it is built this way

*Kind: explanation.*

## The goal

nim-grpc and CiNim use BearSSL for TLS, and some peers they must talk to no longer accept TLS 1.2. Upstream BearSSL has no TLS 1.3. This fork adds it and keeps upstream's character: no `malloc`, fixed buffers, constant-time primitives, small code.

## Handshake in T0, not in C

BearSSL writes its handshake in T0, a small Forth-like language that compiles to a compact state machine. A handshake can then stop at any point when it needs I/O, with no threads and no callbacks. The TLS 1.3 handshake is written in the same files as the 1.2 one (`ssl_hs_client.t0`, `ssl_hs_server.t0`, `ssl_hs_common.t0`), in the same style. The generated C files are committed so that users do not need Mono. Parts that are better in C stay C: the key schedule, the record codecs, key generation and the transcript restart (`src/ssl/ssl_tls13_*.c`, `ssl_rec13_*.c`).

T0 has a data stack and a return stack of 32 entries each. The compiler reports the depth. Several pieces of state therefore live in engine fields (`tls13_*` in `br_ssl_engine_context`) instead of locals: this is why the context grew by 1584 bytes.

## Records and the engine

TLS 1.3 records are encrypted with the real content type inside. The engine got a second pair of record codecs (`br_sslrec13_in_class`, `br_sslrec13_out_class`) with their own vtables, and ignores plaintext ChangeCipherSpec records (the compatibility mode of RFC 8446, appendix D.4).

## Policy handlers

The server's choice of certificate and signature changed in TLS 1.3 (a signature scheme, not a hash and a key type), so `choose13` and `do_sign13` are new methods next to the old ones. The old ones stay for TLS 1.2. This is why a handler written for upstream does not work with TLS 1.3: it has no way to say which scheme it uses.

## Tickets are cache entries

BearSSL has a session cache for TLS 1.2 on the server. A TLS 1.3 ticket is a random 32-byte identifier into the same cache: no encryption key to manage, no new storage. The price: a server restart forgets all tickets, and several servers do not share them. Stateless tickets would need a ticket key and its rotation, and are not implemented.

## What is not here, and why

- **0-RTT**: it needs anti-replay state; the plan excluded it.
- **Ed25519**: BearSSL has no Ed25519 yet.
- **TLS 1.3 only build** (a compile switch that drops TLS 1.2 or TLS 1.3 code): not done; the TLS 1.3 code is in every build, about 12 % of a minimal client or server (see [testing](testing.md)).

## How the code was checked

The key schedule and the record codecs against RFC 8448; a client against RFC 8448's full trace; client and server against OpenSSL, GnuTLS and Go, in both directions; fuzzing. A test of the client against the server in one process cannot find a wrong label that both sides share: only independent implementations found those. See [testing](testing.md) and [security status](explanation-security-status.md).

The full plan with the record of each step: [TLS13-PLAN.md](../TLS13-PLAN.md).
