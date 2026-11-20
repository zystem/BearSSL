# FAQ

*Kind: answers.*

**Is it audited?** No. See [security status](explanation-security-status.md).

**Is TLS 1.3 on by default?** No. Profiles stop at TLS 1.2; you call `br_ssl_engine_set_versions()` and add the suites ([how-to](howto-enable-tls13.md)). `brssl` needs `-vmax TLS-1.3`.

**Will my existing code still work?** If you do not ask for TLS 1.3, it behaves as before: same TLS 1.2 handshake, same speed (1.334 ms of CPU for ECDHE-ECDSA-AES-128-GCM, same as upstream, on one machine). You must rebuild: the engine context and the session parameters are larger, so a binary built against the old headers does not fit.

**Does a server need a session cache for TLS 1.3?** Only for resumption. Without a cache the server never sends tickets and every connection is a full handshake.

**Can I use my own policy handler?** For TLS 1.3 it needs `choose13` and `do_sign13`. The handlers of the library have them.

**Does it support 0-RTT?** No, and there is no plan.

**Does it support Ed25519 certificates?** No.

**Does a TLS 1.3 client talk to a TLS 1.2-only server?** Yes, if its minimum version is TLS 1.2 or lower: it falls back. With `BR_TLS13` as the minimum it fails with `BR_ERR_UNSUPPORTED_VERSION`.

**How much bigger is it?** A minimal client or server grows by about 12 % of its text (+14 KB, 2026-11-20, gcc 13 `-Os`); the engine context grows by 1584 bytes. There is no switch yet to leave TLS 1.3 out.

**Is it faster?** A TLS 1.3 handshake took 1.09 ms of CPU against 1.33 ms for TLS 1.2 on one machine (ECDSA P-256, X25519); the server side takes 40 % less. One machine, one key type; other machines and RSA keys were not measured.

**Does it work from Nim?** nim-grpc ran its tests over TLS 1.3 against a scratch copy; the Nim package is not published. See [contrib/nim](../contrib/nim/README.md).

**Where is the generated reference for `brssl`?** [reference-brssl.md](reference-brssl.md); a test compares it with the program's own usage text.
