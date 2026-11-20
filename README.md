# BearSSL with TLS 1.3

BearSSL is a small, constant-time TLS library in C that does not call `malloc`; this fork adds a TLS 1.3 client and server to it.

**This code has not been audited by anyone outside the project.** The TLS 1.3 handshake is new protocol logic written in 2026. It was tested against OpenSSL, GnuTLS and Go (see [what was run](docs/testing.md)) and fuzzed, and that is all. Read [Security status](docs/explanation-security-status.md) before you use it for anything that matters.

The upstream library is by Thomas Pornin ([bearssl.org](https://www.bearssl.org/)); its own notes are in [README.txt](README.txt). Everything that upstream did (TLS 1.0 to 1.2, the primitives, the X.509 engine) is unchanged.

## When to use it, and when not

Use it when you need TLS 1.3 from a program that already uses BearSSL, or that needs a TLS library with no heap, a small footprint and no dependencies. The reasons it exists: [nim-grpc](https://github.com/zystem/nim-grpc) and CiNim talk to peers that no longer accept TLS 1.2.

Do not use it when:

- you can use a TLS library that has had an independent audit and a long record (OpenSSL, BoringSSL, rustls, Go `crypto/tls`);
- you need 0-RTT, Ed25519 certificates, post-handshake client authentication or tickets that survive a server restart: they are not implemented (see [supported versions and features](docs/supported-versions.md));
- you need a stable binary interface: structures changed (see [the changelog](CHANGELOG.md)) and upstream says the same about itself.

## The parts

```
 your program
     |  br_sslio_* (blocking) or br_ssl_engine_* (state machine, you do the I/O)
     v
 +----------------------------------------------------------+
 | SSL engine  (src/ssl/ssl_engine.c)                       |
 |   handshake written in T0:  ssl_hs_client.t0             |
 |                             ssl_hs_server.t0             |
 |                             ssl_hs_common.t0             |
 |   TLS 1.3 helpers in C:     ssl_tls13_hs.c  key schedule |
 |                             ssl_tls13_ks.c  HKDF         |
 |                             ssl_rec13_*.c   record codecs|
 +----------------------------------------------------------+
     |  hashes, AES-GCM, ChaCha20-Poly1305, EC, RSA, X.509 (unchanged)
     v
 your socket
```

The generated `ssl_hs_*.c` files are committed, so you do not need Mono (the T0 compiler needs it) to build the library.

## Try it (one minute, no hardware)

Needs a C compiler, `make` and `openssl` (only to make a throw-away certificate).

Build the library and the `brssl` tool. `make` prints about 400 compiler commands; this hides them and shows that the tool exists.

<!-- run -->
```bash
make > /dev/null && ls build/brssl build/libbearssl.a
```

```text
build/brssl
build/libbearssl.a
```

Make a self-signed certificate for `localhost` (`openssl` prints nothing here because its progress output is hidden).

<!-- run -->
```bash
mkdir -p /tmp/tls13-tryit && cd /tmp/tls13-tryit
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null
```

Start a TLS 1.3 server (in a second terminal, from the repository directory; the tool prints a list of algorithms when a client connects, cut here):

<!-- run-bg -->
```bash
# in a second terminal
build/brssl server -p 4433 -cert /tmp/tls13-tryit/cert.pem -key /tmp/tls13-tryit/key.pem -vmax TLS-1.3 -alpn h2
```

```text
binding to: ::
bound.
accepting connection from: ::ffff:127.0.0.1
Handshake completed
   version:               TLS 1.3
   cipher suite:          TLS13_AES_128_GCM_SHA256
   ECDHE curve:           Curve25519
   protocol name (ALPN):  h2
hello
SSL closed normally
```

Connect to it with the client (the list of algorithms before "Handshake completed" is cut):

<!-- run -->
```bash
echo hello | build/brssl client localhost:4433 -CA /tmp/tls13-tryit/cert.pem -vmax TLS-1.3 -alpn h2
```

```text
connecting to: 127.0.0.1
connected.
Handshake completed
   version:               TLS 1.3
   cipher suite:          TLS13_AES_128_GCM_SHA256
   ECDHE curve:           Curve25519
   protocol name (ALPN):  h2
stdin closed...
SSL closed normally
```

The server prints `hello`: it received it over TLS 1.3. Without `-vmax TLS-1.3` both tools stop at TLS 1.2, as upstream does: TLS 1.3 is something a program asks for.

Next: [enable TLS 1.3 in your own program](docs/howto-enable-tls13.md). The commands above are run by `sh test/docs_check.sh`.

## Ways to install

There is no installer. You compile the library and link it.

| Way | Use it for | How |
|---|---|---|
| `make` (Unix, `conf/Unix.mk`) | tests, tools, development | `make`; the library is `build/libbearssl.a`, the tool `build/brssl` |
| Copy `inc/` and `src/` into your project | production (embedded, static linking) | compile every `src/**/*.c`, include `inc/` (the upstream way, no new files to list except `src/ssl/ssl_tls13_*.c` and `ssl_rec13_*.c`, which the Makefile finds by itself) |
| The Nim package `bearssl` with this fork's sources | nim-grpc, CiNim | patches in [contrib/nim](contrib/nim/README.md) (not published as a package yet) |

Rebuilding the handshake from the `.t0` files (`make T0`) needs Mono; changing the handshake needs it, using the library does not.

## Words used in these documents

| Word | Meaning |
|---|---|
| Engine | The BearSSL state machine for one connection (`br_ssl_engine_context`); it does no I/O itself. |
| Profile | A function such as `br_ssl_client_init_full()` that fills a context with a set of algorithms. |
| Policy handler | The server object that picks the certificate and signs (`br_ssl_server_policy_class`). Needs `choose13` and `do_sign13` for TLS 1.3. |
| HelloRetryRequest (HRR) | A TLS 1.3 server answer that asks the client for another key-exchange group. |
| Ticket / PSK | A TLS 1.3 session ticket, used as a pre-shared key to resume a session without certificates. |
| mTLS | The client also shows a certificate (mutual TLS). |
| T0 | BearSSL's small language for the handshake code. |

## Where to read next

| You want to | Read |
|---|---|
| know what this is and how far to trust it | [Security status](docs/explanation-security-status.md), [Design](docs/explanation-design.md), [Supported versions and features](docs/supported-versions.md) |
| use it in a C program | [Enable TLS 1.3](docs/howto-enable-tls13.md), [Mutual TLS](docs/howto-mutual-tls.md), [Resume sessions](docs/howto-resumption.md) |
| look something up | [`brssl` options](docs/reference-brssl.md), [API changes](docs/reference-api.md) |
| fix a problem | [Troubleshooting](docs/troubleshooting.md), [FAQ](docs/faq.md) |
| run it in production | [Production checklist](docs/production-checklist.md) |
| use it from Nim | [contrib/nim](contrib/nim/README.md) |
| contribute or check the work | [What was run](docs/testing.md), [TLS13-PLAN.md](TLS13-PLAN.md) (the plan and its records), [Changelog](CHANGELOG.md) |

The whole list, with the kind of each page, is in [docs/README.md](docs/README.md).

## License

MIT, as upstream ([LICENSE.txt](LICENSE.txt)).
