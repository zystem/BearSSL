# How to use client certificates (mutual TLS) with TLS 1.3

*Kind: how-to.* One task: the server asks the client for a certificate, and the client gives one.

Prerequisite: [TLS 1.3 is enabled](howto-enable-tls13.md) on both sides.

## Try it with `brssl`

With the certificate from the [README try-it](../README.md) (a self-signed one is its own trust anchor), the server trusts it as a client certificate and the client presents it:

<!-- run-bg -->
```bash
# in a second terminal
build/brssl server -p 4450 -cert /tmp/tls13-tryit/cert.pem -key /tmp/tls13-tryit/key.pem -vmax TLS-1.3 -CA /tmp/tls13-tryit/cert.pem
```

```text
accepting connection from: ::ffff:127.0.0.1
Handshake completed
   version:               TLS 1.3
hi
SSL closed normally
```

<!-- run -->
```bash
echo hi | build/brssl client localhost:4450 -CA /tmp/tls13-tryit/cert.pem -cert /tmp/tls13-tryit/cert.pem -key /tmp/tls13-tryit/key.pem -vmax TLS-1.3
```

```text
connected.
Handshake completed
   version:               TLS 1.3
stdin closed...
SSL closed normally
```

(The algorithm list is cut. This needs the certificate of the [README try-it](../README.md).) With no `-cert` and `-key` on the client, the server stops the handshake: the client sees `ERROR: SSL error 29 (BR_ERR_NO_CLIENT_AUTH)`. With `-anon_ok` on the server, a client without a certificate is let in (the server code can see that none was given).

## In your server

1. Give the server the trust anchors of the CAs that sign client certificates: `br_ssl_server_set_trust_anchor_names_alt(&sc, tas, n)` (their names go in the CertificateRequest), and set an X.509 engine that validates them: `br_ssl_engine_set_x509()` with a `br_x509_minimal_context` initialised on the same anchors.
2. Allow a missing certificate or not: with `BR_OPT_TOLERATE_NO_CLIENT_AUTH` (`br_ssl_engine_add_flags()`) a client that sends none is accepted; without it, it is refused. Read the validated chain after the handshake with your own `br_x509_class` wrapper if you need the client's name (upstream has no accessor).

The working code is `tools/server.c` (search for `-CA` and `-anon_ok`).

## In your client

Set a certificate handler: `br_ssl_client_set_single_ec()` or `br_ssl_client_set_single_rsa()` with the chain and the key. They have the TLS 1.3 methods (`choose13`, `do_sign13`); a handler of your own written for upstream has not (`choose13 == NULL` means no TLS 1.3 client authentication, the client then sends an empty Certificate). Working code: `tools/client.c` (`-cert`, `-key`).

## What is supported

- Client keys: ECDSA P-256, P-384, P-521 (hash by curve) and RSA-PSS. Not Ed25519.
- The client answers CertificateRequest during the handshake. It does not answer a request after the handshake (post-handshake client authentication is not implemented).
- With a resumed session no certificate is asked for again; the session ticket is only given to a client that was authenticated, if the server asked for authentication.
