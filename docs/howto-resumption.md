# How to resume TLS 1.3 sessions

*Kind: how-to.* One task: the second connection of a client to the same server skips the certificates (one round trip, no signature).

## Try it

[`test/resume_client.c`](../test/resume_client.c) connects twice (it does not validate the certificate: it is a test of the protocol). The server needs a session cache; `brssl server` has one by default (5000 bytes; `-cache N` changes it).

<!-- run-bg -->
```bash
# in a second terminal
build/brssl server -p 4460 -cert /tmp/tls13-tryit/cert.pem -key /tmp/tls13-tryit/key.pem -vmax TLS-1.3 < /dev/null
```

<!-- run -->
```bash
cc -Iinc -o /tmp/resume_client test/resume_client.c build/libbearssl.a && /tmp/resume_client 127.0.0.1 4460
```

```text
connection 1: TLS 1.3, suite 1301, full handshake, -1 bytes read, ticket 32 bytes, error 0
connection 2: TLS 1.3, suite 1301, RESUMED, -1 bytes read, ticket 32 bytes, error 0
```

(`< /dev/null` makes the server close the connection when it has nothing more to say, so that the test program returns; `-1 bytes read`: the test sends a request that the tool does not answer, and the number is not part of the test. The certificate is the one of the [README try-it](../README.md).)

## In your client

1. After the first connection has carried data, call `br_ssl_engine_get_session_parameters(eng, &sp)`. A TLS 1.3 server sends its ticket after the handshake, so **do not take the parameters right after the handshake**: take them after you have read the first records (or at the end of the connection). `sp.ticket_len` is non-zero when a ticket has arrived.
2. For the next connection: `br_ssl_engine_set_session_parameters(eng, &sp)` and `br_ssl_client_reset(&cc, host, 1)` (the last argument asks for resumption).
3. `br_ssl_engine_tls13_resumed(eng)` tells whether the connection was resumed (a server that forgot the ticket gives a full handshake, with no error).

The client keeps one ticket, up to 512 bytes (`BR_TLS13_MAX_TICKET`). The server sends a new ticket on a resumed connection too; take it the same way and use it next time. The old one stays valid until the server's cache drops it.

## In your server

Give the server a session cache, as for TLS 1.2: `br_ssl_session_cache_lru_init()` and `br_ssl_server_set_cache()`. The server's ticket is an identifier of an entry in this cache (32 bytes): there are no tickets that you can decrypt, and **a server restart, or an entry that the cache dropped, means a full handshake**. If several server processes serve one name, a ticket from one is not known to the others.

`br_ssl_engine_tls13_ticket_count()` tells how many tickets the server has sent on this connection.

### Time, policy and client certificates

- **Give the engines a clock** with `br_ssl_engine_set_tls13_time(eng, seconds)` before each `br_ssl_client_reset()` / `br_ssl_server_reset()`: seconds on a steady clock (`CLOCK_MONOTONIC` is enough for a process that does not restart; use the wall clock if saved sessions outlive it). With it the client sends the real age of the ticket and does not offer a ticket older than its lifetime, and the server does not resume a session that has reached 7 days (the client refuses at the lifetime of the ticket, at most 7 days: the same boundary). `test/resume_client.c` sets the clock and requires it. **Without a clock a ticket never expires on its own.**
- **Policy identifier**: `br_ssl_server_set_tls13_policy_id(&sc, id)`. Add one to `id` whenever the trust anchors for client certificates, the need for client certificates, or the server certificate change: sessions saved earlier are then not resumed.
- A server that asks for client certificates resumes only a session in which the client had used one; any other client gets a full handshake and is asked for its certificate. A session created without client authentication is never turned into an authenticated one by resumption.
- **Who is the client after a resumption?** `br_ssl_engine_tls13_client_cert_hash(&sc.eng, hash)` gives, after any handshake, resumed or not, the SHA-256 of the certificate with which the client authenticated itself (the value of a resumed session is read from the cache, not from the client). A program that decides by the identity of the client uses it every time and needs no full handshake for it. Keep one cache per trust domain, or put the domain in the policy identifier, and change the identifier when a client is revoked or the trust anchors change: the sessions of the old policy are then not resumed.
- **A clock is missing**: `br_ssl_engine_set_tls13_clock_required(eng, 1)` makes the engine skip tickets until it has the time (a full handshake instead).
- **The secrets in the cache**: `br_ssl_session_cache_lru_forget()` overwrites the secret of the entry at once; `br_ssl_session_cache_lru_wipe()` overwrites the whole storage (call it before the storage is released or reused). A `br_ssl_session_parameters` that you saved holds the resumption secret: wipe it when you drop it.
- The entries of the LRU cache are 144 bytes (`br_ssl_session_cache_lru_init()` storage size divided by 144 is the number of sessions).

## Limits

- Only `psk_dhe_ke` (a fresh key exchange each time) is supported. A client that offers only `psk_ke` gets a full handshake.
- Resumption needs the same cipher suite hash as the first connection.
- The server does not check the ticket's age and does not mark a ticket as used: a ticket can be presented again until its cache entry is dropped. A ticket also needs the PSK that only the client has (the binder is checked), but do not use a resumed connection as proof of anything beyond "the same client as before". 0-RTT is not implemented; that is what makes this acceptable.
- The lifetime in the ticket is 604800 s (7 days); the cache may drop an entry sooner.
