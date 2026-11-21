# Production checklist

*Kind: checklist.* Things to settle before this library carries real traffic. The answer to some of them is "this library does not do that"; that is written, not hidden.

- [ ] **Accept the risk.** The TLS 1.3 code is not independently audited ([security status](explanation-security-status.md)). If that is not acceptable, use an audited library.
- [ ] **Rebuild everything** that includes `bearssl_ssl.h` (structures changed, [API changes](reference-api.md)).
- [ ] **Versions and suites are set on purpose**: the TLS 1.3 suites, the minimum version (`BR_TLS12`, or `BR_TLS13` if every peer can), and no suites you do not need.
- [ ] **Certificates**: the server certificate and the chain fit the I/O buffer (use `BR_SSL_BUFSIZE_BIDI`, as the samples do). Plan the renewal: the library reads no files and has no reload; your program replaces the chain and the key and the next connection uses them.
- [ ] **Private keys**: stored and backed up outside the library; BearSSL keeps a key in memory for the life of the policy handler. Wipe your own copies.
- [ ] **Trust anchors** for clients, and for servers that ask for client certificates; there is no revocation checking (CRL or OCSP) in BearSSL: handle revocation by short certificate lifetimes or in your program.
- [ ] **Client certificates** (if used): required or optional (`BR_OPT_TOLERATE_NO_CLIENT_AUTH`), and the program that reads the identity of the client checks it after the handshake.
- [ ] **Resumption rules**: give the engines a clock (`br_ssl_engine_set_tls13_time()`; without it a ticket does not expire by itself) and set a policy identifier on the server (`br_ssl_server_set_tls13_policy_id()`) that you change when the client-certificate policy or the server certificate changes ([resumption](howto-resumption.md)).
- [ ] **Session cache** (resumption): size it (`br_ssl_session_cache_lru_init()` storage; the default of `brssl` is 5000 bytes). A restart forgets all tickets; several servers do not share them; no stateless tickets.
- [ ] **Randomness**: the engine needs a seeded PRNG (`br_ssl_engine_inject_entropy()` or the system source). As upstream, an unseeded PRNG gives `BR_ERR_NO_RANDOM`; this was not run with TLS 1.3.
- [ ] **Network**: your program does the I/O and the time-outs; the engine has none. Set a handshake time-out.
- [ ] **Logging**: log `br_ssl_engine_last_error()` with the number from [troubleshooting](troubleshooting.md); BearSSL logs nothing.
- [ ] **Upgrades**: upstream fixes are merged by hand in this fork; watch both repositories. Rebuild after each update.
- [ ] **Tests on your side**: connect to your real peers with each version you allow; resume; run with a peer that sends HelloRetryRequest (set `openssl s_server -groups` to one group); KeyUpdate from the peer (`openssl s_client`, `k`).
- [ ] **Drills**: replace a certificate while the service runs; restart the server and see that clients do a full handshake and recover; try a peer that offers only TLS 1.2.
- [ ] **Not available**: 0-RTT, Ed25519, post-handshake client authentication, stateless tickets, a compile switch to leave TLS 1.3 out. If you need one of these, this library is not ready.
