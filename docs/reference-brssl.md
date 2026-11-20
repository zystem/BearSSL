# `brssl` reference

*Kind: reference.* Options of the `brssl client` and `brssl server` commands that matter for TLS 1.3, and the full usage text. The usage blocks are compared with the program's own output by `sh test/docs_check.sh`; if an option is added without a line here, that test fails.

## Defaults that decide whether TLS 1.3 is used

| Setting | Default | Notes |
|---|---|---|
| `-vmin` | `TLS-1.0` | Names: `TLS-1.0`, `TLS-1.1`, `TLS-1.2`, `TLS-1.3`; `-list` prints the short forms `tls10` to `tls13`, which also work. |
| `-vmax` | `TLS-1.2` | **TLS 1.3 is off unless you pass `-vmax TLS-1.3`.** The same is true of programs that use the library: see [enable TLS 1.3](howto-enable-tls13.md). |
| `-cs` (cipher suites) | every suite of the tool's list up to `-vmax` (the TLS 1.3 ones only when `-vmax TLS-1.3`) | TLS 1.3 suites: `TLS13_AES_128_GCM_SHA256`, `TLS13_AES_256_GCM_SHA384`, `TLS13_CHACHA20_POLY1305_SHA256`. With `-cs` you list names; list only TLS 1.3 names and `-vmin TLS-1.3` for a TLS 1.3-only run. |
| `-p` (server) | `4433` | |
| `-cache` (server) | 5000 bytes | The server's tickets are entries of this cache (see [resumption](howto-resumption.md)): a small cache forgets tickets early. |
| `-alpn` | none | May be repeated; `-strictalpn` (server) refuses a client that shares no name (alert 120). |
| `-CA` (server) | none | Asks the client for a certificate and trusts these anchors. Without `-anon_ok` a client with no certificate is refused (`BR_ERR_NO_CLIENT_AUTH`). |
| `-cert`, `-key` (client) | none | The client's certificate chain and key for mutual TLS. ECDSA P-256/384/521 and RSA keys work with TLS 1.3. |
| changing a setting | takes effect for the next process | The tool has no reload. |

## Exit status and errors

The tool prints `ERROR: SSL error N (NAME)` and exits with a non-zero status when the connection fails. An alert from the peer is `256 + alert number`; an alert we send is `512 + alert number` (for example `376` is "received alert 120", `632` is "sent alert 120"). See [troubleshooting](troubleshooting.md).

## `brssl client`

<!-- usage: build/brssl client -h -->
```text
usage: brssl client server[:port] [ options ]
options:
   -q              suppress verbose messages
   -trace          activate extra debug messages (dump of all packets)
   -sni name       use this specific name for SNI
   -nosni          do not send any SNI
   -mono           use monodirectional buffering
   -buf length     set the I/O buffer length (in bytes)
   -CA file        add certificates in 'file' to trust anchors
   -cert file      set client certificate chain
   -key file       set client private key (for certificate authentication)
   -nostaticecdh   prohibit full-static ECDH (client certificate)
   -list           list supported names (protocols, algorithms...)
   -vmin name      set minimum supported version (default: TLS-1.0)
   -vmax name      set maximum supported version (default: TLS-1.2)
   -cs names       set list of supported cipher suites (comma-separated)
   -hf names       add support for some hash functions (comma-separated)
   -minhello len   set minimum ClientHello length (in bytes)
   -fallback       send the TLS_FALLBACK_SCSV (i.e. claim a downgrade)
   -noreneg        prohibit renegotiations
   -alpn name      add protocol name to list of protocols (ALPN extension)
   -strictalpn     fail on ALPN mismatch
```

## `brssl server`

<!-- usage: build/brssl server -h -->
```text
usage: brssl server [ options ]
options:
   -q              suppress verbose messages
   -trace          activate extra debug messages (dump of all packets)
   -b name         bind to a specific address or host name
   -p port         bind to a specific port (default: 4433)
   -mono           use monodirectional buffering
   -buf length     set the I/O buffer length (in bytes)
   -cache length   set the session cache storage length (in bytes)
   -cert fname     read certificate chain from file 'fname'
   -key fname      read private key from file 'fname'
   -CA file        add trust anchors from 'file' (for client auth)
   -anon_ok        request but do not require a client certificate
   -list           list supported names (protocols, algorithms...)
   -vmin name      set minimum supported version (default: TLS-1.0)
   -vmax name      set maximum supported version (default: TLS-1.2)
   -cs names       set list of supported cipher suites (comma-separated)
   -hf names       add support for some hash functions (comma-separated)
   -cbhash         test hashing in policy callback
   -serverpref     enforce server's preferences for cipher suites
   -noreneg        prohibit renegotiations
   -alpn name      add protocol name to list of protocols (ALPN extension)
   -strictalpn     fail on ALPN mismatch
```

## Supported names (`-list`)

<!-- usage: build/brssl client -list -->
```text
Protocol versions:
   tls10    TLS 1.0
   tls11    TLS 1.1
   tls12    TLS 1.2
   tls13    TLS 1.3
Hash functions:
   md5      MD5
   sha1     SHA-1
   sha224   SHA-224
   sha256   SHA-256
   sha384   SHA-384
   sha512   SHA-512
Cipher suites:
   TLS13_AES_128_GCM_SHA256
        TLS 1.3, AES-128/GCM + SHA-256
   TLS13_AES_256_GCM_SHA384
        TLS 1.3, AES-256/GCM + SHA-384
   TLS13_CHACHA20_POLY1305_SHA256
        TLS 1.3, ChaCha20+Poly1305 + SHA-256
   ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        ECDHE with ECDSA, ChaCha20+Poly1305 encryption (TLS 1.2+)
   ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        ECDHE with RSA, ChaCha20+Poly1305 encryption (TLS 1.2+)
   ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        ECDHE with ECDSA, AES-128/GCM encryption (TLS 1.2+)
   ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ECDHE with RSA, AES-128/GCM encryption (TLS 1.2+)
   ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        ECDHE with ECDSA, AES-256/GCM encryption (TLS 1.2+)
   ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ECDHE with RSA, AES-256/GCM encryption (TLS 1.2+)
   ECDHE_ECDSA_WITH_AES_128_CCM
        ECDHE with ECDSA, AES-128/CCM encryption (TLS 1.2+)
   ECDHE_ECDSA_WITH_AES_256_CCM
        ECDHE with ECDSA, AES-256/CCM encryption (TLS 1.2+)
   ECDHE_ECDSA_WITH_AES_128_CCM_8
        ECDHE with ECDSA, AES-128/CCM_8 encryption (TLS 1.2+)
   ECDHE_ECDSA_WITH_AES_256_CCM_8
        ECDHE with ECDSA, AES-256/CCM_8 encryption (TLS 1.2+)
   ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        ECDHE with ECDSA, AES-128/CBC + SHA-256 (TLS 1.2+)
   ECDHE_RSA_WITH_AES_128_CBC_SHA256
        ECDHE with RSA, AES-128/CBC + SHA-256 (TLS 1.2+)
   ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        ECDHE with ECDSA, AES-256/CBC + SHA-384 (TLS 1.2+)
   ECDHE_RSA_WITH_AES_256_CBC_SHA384
        ECDHE with RSA, AES-256/CBC + SHA-384 (TLS 1.2+)
   ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        ECDHE with ECDSA, AES-128/CBC + SHA-1
   ECDHE_RSA_WITH_AES_128_CBC_SHA
        ECDHE with RSA, AES-128/CBC + SHA-1
   ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        ECDHE with ECDSA, AES-256/CBC + SHA-1
   ECDHE_RSA_WITH_AES_256_CBC_SHA
        ECDHE with RSA, AES-256/CBC + SHA-1
   ECDH_ECDSA_WITH_AES_128_GCM_SHA256
        ECDH key exchange (EC cert), AES-128/GCM (TLS 1.2+)
   ECDH_RSA_WITH_AES_128_GCM_SHA256
        ECDH key exchange (RSA cert), AES-128/GCM (TLS 1.2+)
   ECDH_ECDSA_WITH_AES_256_GCM_SHA384
        ECDH key exchange (EC cert), AES-256/GCM (TLS 1.2+)
   ECDH_RSA_WITH_AES_256_GCM_SHA384
        ECDH key exchange (RSA cert), AES-256/GCM (TLS 1.2+)
   ECDH_ECDSA_WITH_AES_128_CBC_SHA256
        ECDH key exchange (EC cert), AES-128/CBC + HMAC/SHA-256 (TLS 1.2+)
   ECDH_RSA_WITH_AES_128_CBC_SHA256
        ECDH key exchange (RSA cert), AES-128/CBC + HMAC/SHA-256 (TLS 1.2+)
   ECDH_ECDSA_WITH_AES_256_CBC_SHA384
        ECDH key exchange (EC cert), AES-256/CBC + HMAC/SHA-384 (TLS 1.2+)
   ECDH_RSA_WITH_AES_256_CBC_SHA384
        ECDH key exchange (RSA cert), AES-256/CBC + HMAC/SHA-384 (TLS 1.2+)
   ECDH_ECDSA_WITH_AES_128_CBC_SHA
        ECDH key exchange (EC cert), AES-128/CBC + HMAC/SHA-1
   ECDH_RSA_WITH_AES_128_CBC_SHA
        ECDH key exchange (RSA cert), AES-128/CBC + HMAC/SHA-1
   ECDH_ECDSA_WITH_AES_256_CBC_SHA
        ECDH key exchange (EC cert), AES-256/CBC + HMAC/SHA-1
   ECDH_RSA_WITH_AES_256_CBC_SHA
        ECDH key exchange (RSA cert), AES-256/CBC + HMAC/SHA-1
   RSA_WITH_AES_128_GCM_SHA256
        RSA key exchange, AES-128/GCM encryption (TLS 1.2+)
   RSA_WITH_AES_256_GCM_SHA384
        RSA key exchange, AES-256/GCM encryption (TLS 1.2+)
   RSA_WITH_AES_128_CCM
        RSA key exchange, AES-128/CCM encryption (TLS 1.2+)
   RSA_WITH_AES_256_CCM
        RSA key exchange, AES-256/CCM encryption (TLS 1.2+)
   RSA_WITH_AES_128_CCM_8
        RSA key exchange, AES-128/CCM_8 encryption (TLS 1.2+)
   RSA_WITH_AES_256_CCM_8
        RSA key exchange, AES-256/CCM_8 encryption (TLS 1.2+)
   RSA_WITH_AES_128_CBC_SHA256
        RSA key exchange, AES-128/CBC + HMAC/SHA-256 (TLS 1.2+)
   RSA_WITH_AES_256_CBC_SHA256
        RSA key exchange, AES-256/CBC + HMAC/SHA-256 (TLS 1.2+)
   RSA_WITH_AES_128_CBC_SHA
        RSA key exchange, AES-128/CBC + HMAC/SHA-1
   RSA_WITH_AES_256_CBC_SHA
        RSA key exchange, AES-256/CBC + HMAC/SHA-1
   ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
        ECDHE with ECDSA, 3DES/CBC + SHA-1
   ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        ECDHE with RSA, 3DES/CBC + SHA-1
   ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
        ECDH key exchange (EC cert), 3DES/CBC + HMAC/SHA-1
   ECDH_RSA_WITH_3DES_EDE_CBC_SHA
        ECDH key exchange (RSA cert), 3DES/CBC + HMAC/SHA-1
   RSA_WITH_3DES_EDE_CBC_SHA
        RSA key exchange, 3DES/CBC + HMAC/SHA-1
```
