# How to resume TLS 1.3 sessions

*Kind: how-to.* One task: the second connection of a client to the same server skips the certificates (one round trip, no signature).

## Try it

[`test/resume_client.c`](../test/resume_client.c) connects twice (it does not validate the certificate: it is a test of the protocol). The server needs a session cache; `brssl server` has one by default (5000 bytes; `-cache N` changes it).

<!-- run-bg -->
```bash
# in a second terminal
build/brssl server -p 4460 -cert /tmp/tls13-tryit/cert.pem -key /tmp/tls13-tryit/key.pem -vmax TLS-1.3
```

<!-- run -->
```bash
cc -Iinc -o /tmp/resume_client test/resume_client.c build/libbearssl.a && /tmp/resume_client 127.0.0.1 4460
```

```text
connection 1: TLS 1.3, suite 1301, full handshake, -1 bytes read, ticket 32 bytes, error 0
connection 2: TLS 1.3, suite 1301, RESUMED, -1 bytes read, ticket 32 bytes, error 0
```

(`-1 bytes read`: the test sends a request that the tool does not answer; the number is not part of the test. The certificate is the one of the [README try-it](../README.md).)

## In your client

1. After the first connection has carried data, call `br_ssl_engine_get_session_parameters(eng, &sp)`. A TLS 1.3 server sends its ticket after the handshake, so **do not take the parameters right after the handshake**: take them after you have read the first records (or at the end of the connection). `sp.ticket_len` is non-zero when a ticket has arrived.
2. For the next connection: `br_ssl_engine_set_session_parameters(eng, &sp)` and `br_ssl_client_reset(&cc, host, 1)` (the last argument asks for resumption).
3. `br_ssl_engine_tls13_resumed(eng)` tells whether the connection was resumed (a server that forgot the ticket gives a full handshake, with no error).

The client keeps one ticket, up to 512 bytes (`BR_TLS13_MAX_TICKET`). The server sends a new ticket on a resumed connection too; take it the same way and use it next time. The old one stays valid until the server's cache drops it.

## In your server

Give the server a session cache, as for TLS 1.2: `br_ssl_session_cache_lru_init()` and `br_ssl_server_set_cache()`. The server's ticket is an identifier of an entry in this cache (32 bytes): there are no tickets that you can decrypt, and **a server restart, or an entry that the cache dropped, means a full handshake**. If several server processes serve one name, a ticket from one is not known to the others.

`br_ssl_engine_tls13_ticket_count()` tells how many tickets the server has sent on this connection.

## Limits

- Only `psk_dhe_ke` (a fresh key exchange each time) is supported. A client that offers only `psk_ke` gets a full handshake.
- Resumption needs the same cipher suite hash as the first connection.
- The server does not check the ticket's age and does not mark a ticket as used: a ticket can be presented again until its cache entry is dropped. A ticket also needs the PSK that only the client has (the binder is checked), but do not use a resumed connection as proof of anything beyond "the same client as before". 0-RTT is not implemented; that is what makes this acceptable.
- The lifetime in the ticket is 604800 s (7 days); the cache may drop an entry sooner.
