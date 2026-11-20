# How to enable TLS 1.3 in your program

*Kind: how-to.* One task: make a client or a server that you already have use TLS 1.3 when the peer can.

## Why it is not on already

The profile functions (`br_ssl_client_init_full()`, `br_ssl_server_init_full_ec()`, `br_ssl_server_init_full_rsa()`, and the smaller ones) set versions TLS 1.0 to 1.2 and a list of TLS 1.2 suites, as upstream does. A program built before this fork behaves as before. You ask for TLS 1.3 yourself.

## Steps

1. Call the profile function as you do now.
2. Set the versions and the suite list. [`samples/tls13.h`](../samples/tls13.h) is a working helper (it is compiled and run by `sh test/docs_check.sh`):

   ```c
   static const uint16_t suites[] = {
       BR_TLS13_AES_128_GCM_SHA256,
       BR_TLS13_AES_256_GCM_SHA384,
       BR_TLS13_CHACHA20_POLY1305_SHA256,
       BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
       BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
       BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
       BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
   };

   br_ssl_engine_set_versions(eng, BR_TLS12, BR_TLS13);
   br_ssl_engine_set_suites(eng, suites, sizeof suites / sizeof suites[0]);
   ```

   `eng` is `&cc.eng` of the client context or `&sc.eng` of the server context. Call this before `br_ssl_client_reset()` or `br_ssl_server_reset()`.
3. TLS 1.3 only: remove the TLS 1.2 suites and use `br_ssl_engine_set_versions(eng, BR_TLS13, BR_TLS13)`. A peer that offers only TLS 1.2 is then refused with `BR_ERR_UNSUPPORTED_VERSION` (3).

## What the profile must have

The "full" profiles have all of this. If you built your own profile (see `samples/custom_profile.c`), it needs:

- SHA-256 and SHA-384 registered with `br_ssl_engine_set_hash()` (the engine hashes the handshake with the hash of the suite);
- AES-GCM (`br_ssl_engine_set_default_aes_gcm()`) and/or ChaCha20+Poly1305 (`br_ssl_engine_set_default_chapol()`), for the suites that you list;
- an RSA-PSS verifier: `br_ssl_engine_set_default_rsavrfy()` installs it (a custom verifier set with `br_ssl_engine_set_rsavrfy()` does not; set `br_ssl_engine_set_rsapssvrfy()` too);
- on a server, a policy handler that has the `choose13` and `do_sign13` methods. The handlers of the library (`br_ssl_server_set_single_rsa()`, `br_ssl_server_set_single_ec()`) have them. A handler of your own that was written for upstream has not: it works for TLS 1.2 and cannot be used for TLS 1.3. The same holds for the client certificate handler (see [mutual TLS](howto-mutual-tls.md)).

## Check that it worked

After the handshake, `br_ssl_engine_get_session_parameters()` gives `version`; it is `BR_TLS13` (0x0304) for TLS 1.3. `samples/client_basic.c` prints it when built with `-DWITH_TLS13`:

<!-- run -->
```bash
cc -DWITH_TLS13 -Iinc -Isamples -o /tmp/client_basic samples/client_basic.c build/libbearssl.a
cc -DWITH_TLS13 -Iinc -Isamples -o /tmp/server_basic samples/server_basic.c build/libbearssl.a
```

Start the server in a second terminal:

<!-- run-bg -->
```bash
# in a second terminal
/tmp/server_basic 4430
```

Then run the client (the server's output is empty):

<!-- run -->
```bash
/tmp/client_basic localhost 4430 / | head -3
```

```text
connected.
version 0x0304
closed.
HTTP/1.0 200 OK
```

Without `-DWITH_TLS13` the same programs negotiate TLS 1.2.

## Other things you can set

- ALPN: `br_ssl_engine_set_protocol_names()` on both sides. On a server, a name that no one shares gives alert 120 (`no_application_protocol`) before the policy handler is called, as with TLS 1.2.
- The record size limit (RFC 8449) is offered by the client and accepted from the peer; `br_ssl_engine_set_buffer()` sizes still decide what you can receive.

If it does not work, see [troubleshooting](troubleshooting.md).
