# What other TLS projects taught us

*Kind: record.* What was learnt from the TLS 1.3 implementations on the [TLS working group list](https://github.com/tlswg/tlswg-wiki/blob/main/IMPLEMENTATIONS.md): scripts run against our server, other libraries as peers, and problems reported (and closed) in their issue trackers, checked against our code. Dates are 2026-11-21. "Not run" means exactly that. What was fixed because of it is in [../CHANGELOG.md](../CHANGELOG.md); what is not implemented is in [supported-versions.md](supported-versions.md).

## Method

1. **tlsfuzzer** (Python, tests a server with correct and with broken handshakes; commit `51aad6e`, with tlslite-ng `7e95ea1`): all 57 `test-tls13-*.py` scripts against `test/tlsfuzzer/server.c` (the sample server with an echo and a child process per connection), RSA key, Linux x86-64, gcc 13. 2927 probes in all. `sh test/tlsfuzzer/run.sh` repeats the part that must pass (about 35 s); `ALL=1` prints the table for every script.
2. **picotls** (`e999a3d`, C): its `cli` as client and as server against `brssl` and the sample server, one connection each way, and a client that asks for HelloRetryRequest (`-n`): all worked. Resumption with picotls was **not run** (the sample server has no session cache, and the `brssl` server takes one connection).
3. **Issue trackers** of picotls, wolfSSL, rustls and OpenSSL (`gh search issues`, closed issues): the ones about TLS 1.3 conformance and security were read and compared with our code (table below).
4. Already run before: OpenSSL, GnuTLS and Go ([testing.md](testing.md)).

## Result of tlsfuzzer

| | Passed | Failed |
|---|---|---|
| Before the fixes below (echo server, same scripts) | 1770 | 1157 |
| After | 1852 | 1075 |

Scripts that pass in full now: `conversation`, `count-tickets`, `finished` (714 probes; 2 before), `hrr` (3; 2 before), `invalid-ciphers`, `large-number-of-extensions`, `lengths` (1002), `nociphers`, `pkcs-signature`, `record-padding`, `rsa-signatures`, `unencrypted-alert`, and `ecdhe-curves` except the X448 probes (28 of 33; 6 before). Several scripts draw a part of their probes at random, so a run of the gate does not try all of them (`finished` is run in full). Every probe of every script of the gate was run once on 2026-11-28 (`-n 0`, 530 s; `lengths` alone has 16 386): no failure apart from the expected ones.

The 1075 that still fail are, as far as they were looked at:

| Cause | Where | Probes (about) |
|---|---|---|
| A feature that is not implemented | finite-field groups (`ffdhe-*`, 69), Brainpool (23), certificate compression (20), 0-RTT (8), X448 (5), Ed25519/Ed448 (2); ML-KEM, ML-DSA and post-handshake authentication scripts do not start | 130 |
| The connection is closed **without the alert** that tlsfuzzer expects | `keyupdate` (59), `record-layer-limits` (61), `signature-algorithms` (89: a length inside the extension that is wrong), `symetric-ciphers` (100: a flipped bit in the tag or the data), `empty-alert` (8), `multiple-ccs-messages` (5), `zero-content-type` (4), `ccs` (2), `keyshare-omitted` (3), `finished-plaintext` (1) | 330 |
| Resumption scripts: the server of the harness serves each connection in a new process, so a ticket is never found | `session-resumption`, `psk_ke`, `psk_dhe_ke` | 13 |
| Our answer differs from what the script expects | `legacy-version` (8: we accept a `legacy_version` below 0x0303 because the `supported_versions` extension decides, RFC 8446 section 4.2.1; the script wants an alert) | 8 |
| **Not looked at** | `version-negotiation` (196), `serverhello-random` (96, they use finite-field groups), `obsolete-curves` (164), `unrecognised-groups`, `no-unknown-groups` (3), `zero-length-data` (9, six of them time out), `connection-abort` (10), `minerva`, `rsapss-signatures`, `ecdsa-support`, `shuffled-extentions` (17, the same HelloRetryRequest probes) | the rest |

The silent close is how upstream BearSSL treats most errors, in TLS 1.2 as well: it fails the connection and sends an alert only in some cases ([../inc/bearssl_ssl.h](../inc/bearssl_ssl.h), `BR_ERR_SEND_FATAL_ALERT`). RFC 8446 says which alert to send in many of these cases. Sending them everywhere would change a design choice of the library, in particular for the record layer (a bad tag, an empty record, a record that is too long), where the engine cannot write a record once it has failed. This was **not** done. It is the largest group of failures and the first thing to decide if the fork should be strict.

RFC 9846 has since replaced RFC 8446 and asks for the alert on `legacy_version` that the table above calls a difference: [rfc9846.md](rfc9846.md).

The table and the paragraph above are the state of 2026-11-21. What changed with the alerts:

## Alerts for errors (2026-11-27)

The fork now sends a fatal alert for a TLS 1.3 error in both roles ([reference-api.md](reference-api.md), "Alerts on errors"); TLS 1.2 and older behave as upstream. All 57 scripts again, the same harness, Linux x86-64, gcc 13, before and after the change:

| | Passed | Failed |
|---|---|---|
| master before the change | 1853 | 1074 |
| with the alerts | 2533 | 775 |

(The totals differ because some scripts draw their probes at random or stop early when the first ones fail; `dhe-shared-secret-padding` alone went from 3 probes to 384.) No probe now ends with "Unexpected closure from peer" (232 did before). `keyupdate`, `record-layer-limits`, `empty-alert` and `finished-plaintext` pass and are in the gate of `run.sh`; one `keyupdate` probe is left out of it, because it sends a line in two pieces and the test server, which echoes what it has read, now and then answers the first piece alone. The client role was tested with `testcrypto` (`TLS13_TAMPER`, `TLS13_ALERTS`) and the interop scripts; tlsfuzzer tests a server only.

The scripts found two things that were not about alerts, both now refused with `unexpected_message` (RFC 8446 section 5.1): application data in the middle of a KeyUpdate that came in pieces, and a second KeyUpdate in the same record, after the key had changed.

Four things seen in what still failed were looked at on 2026-11-28:

| Seen | Cause | Now |
|---|---|---|
| A ChangeCipherSpec after the handshake was ignored (`ccs`, 1 probe) | The engine dropped it at any time | `unexpected_message`; a protected record of that type too (RFC 9846 section 5) |
| ChangeCipherSpec records right after the ClientHello ended with `protocol_version` (`multiple-ccs-messages`, 4 probes and its sanity probe) | The version of the record header was compared with that of the ClientHello (0x0301), which TLS 1.3 says to ignore | The version of an unprotected record is ignored once TLS 1.3 is chosen. A protected record keeps the check, because nothing else covers that byte. Three probes still want an alert for a second ChangeCipherSpec before the Finished; the RFC says to drop every one, so they are expected failures in `run.sh` |
| An empty list of signature algorithms got `handshake_failure` (`signature-algorithms`, 1 probe) | Read like a list with nothing usable | `decode_error` |
| Two probes of `zero-content-type` got application data, not an alert | **The test server, not the library**: the script sends a line in two pieces and the server echoed the first piece before it read the bad record | The test server answers when what it has read ends with a newline; the probes pass, and the `keyupdate` probe that was left out for the same reason is back in the gate |

Found on the way: a server context that was used for a second connection kept the mark of the first one until the new ClientHello was processed; `br_ssl_engine_hs_reset()` now clears it. `ccs`, `zero-content-type`, `signature-algorithms` and `multiple-ccs-messages` are in the gate. All 57 scripts afterwards: 2168 probes passed, 760 failed (the totals vary between runs). The rest are features that are not implemented (finite-field groups, CCM suites, compression, 0-RTT), the resumption scripts that the test server cannot serve, and scripts **not looked at**.

## Fixed because of it (2026-11-21)

| Found by | Fault | Fix |
|---|---|---|
| tlsfuzzer `ecdhe-curves`; [OpenSSL #33460](https://github.com/openssl/openssl/issues/33460); the review of 2026-11-21 | The server accepted an X25519 key share that is a point of small order (the shared secret is all zero, RFC 8446 section 7.4.2), and a key share with a point not on the curve or of a wrong length, and failed only after it had sent its ServerHello | The shared secret is computed and checked **before** the ServerHello (`br_ssl_engine_tls13_srv_ecdh`); a zero X25519 secret, an invalid point and a share of a wrong length end with `illegal_parameter`. The client checks the zero secret too |
| tlsfuzzer `hrr`, `no-unknown-groups` | After a HelloRetryRequest the server sent its ChangeCipherSpec after the ServerHello, not after the first message (RFC 8446 appendix D.4) | The ChangeCipherSpec follows the HelloRetryRequest, not the ServerHello (found while testing: the record type must be reset to Handshake after it, or OpenSSL stops with "invalid ccs message") |
| tlsfuzzer `finished`; [picotls #605](https://github.com/h2o/picotls/issues/605) | A wrong or too long Finished, or a message of the wrong type in the client's flight, closed the connection with no alert | `decrypt_error`, `decode_error` and `unexpected_message` are sent (the status of the engine is still `BR_ERR_BAD_FINISHED` or `BR_ERR_UNEXPECTED`) |
| tlsfuzzer `empty-alert`; [picotls #605](https://github.com/h2o/picotls/issues/605) | A TLS 1.3 Handshake or Alert record with no content was skipped; the engine then waited for more | It fails with `BR_ERR_UNEXPECTED` (on 2026-11-21 without an alert; since 2026-11-27 with one) |

## Fixed because of the review of 2026-11-21

The expert review of this tree ([`SECURITY-REVIEW-2026-11-21.en.md`](../SECURITY-REVIEW-2026-11-21.en.md), revision `9f8cded`) named five faults and some smaller ones. Each has a test; for the three session rules, the KeyUpdate and the record length the test was seen to fail with the fix taken out.

| Finding of the review | Fix | Test |
|---|---|---|
| X25519: no check of an all-zero shared secret | See the first table | tlsfuzzer `ecdhe-curves` ("x25519 - point at infinity") |
| A session is resumed under another authentication policy; a session of an unauthenticated client skips client authentication | A policy identifier (`br_ssl_server_set_tls13_policy_id()`) and the "client used a certificate" flag are stored with the session; a server that asks for client certificates resumes only an authenticated session | `TLS13_SESSION` in `testcrypto` |
| Ticket lifetime: the client sends an age of 0, nothing expires | With a clock (`br_ssl_engine_set_tls13_time()`): the true age is sent, a ticket older than its lifetime (at most 7 days) is not offered, and the server does not resume an older session. Without a clock nothing changes (documented) | `TLS13_SESSION` |
| No KeyUpdate before the limit of AES-GCM | The engine sends one after 2^24 records (2^32 with ChaCha20-Poly1305) or after `br_ssl_engine_set_tls13_key_update_interval()` records, and stops with `BR_ERR_KEY_LIMIT` at the limit | `TLS13_KEYUPDATE`; interop: OpenSSL and GnuTLS read on after our updates (`-ku 2`) |
| The length of a protected record: the inner plaintext may be at most 2^14 + 1 bytes, padding included | Both codecs refuse a longer record | `TLS13_REC` (both ciphers, both sides of the limit) |
| The wipe of a PSK in `br_ssl_server_tls13_psk_lookup` is removed by the optimiser | `br_tls13_wipe()` (writes through a volatile pointer) for the secrets of the TLS 1.3 code, on every path, including the HKDF contexts and the traffic keys | `TLS13_KS` (the function); the object code was not inspected |
| The padding of a record is removed in a time that depends on its length | The inner type is looked for with the same work for any padding (`br_tls13_find_type()`) | `TLS13_KS`; timing was not measured |
| When are the handshake secrets and the master secret wiped? The context is not wiped when the connection ends | The handshake traffic secrets, the key schedule (master secret), the PSK and the key exchange values are wiped when the handshake is over; every TLS 1.3 secret, the resumption secret and the keys of the record codecs are wiped when the engine fails or is closed (`br_ssl_engine_tls13_wipe()`, called from `br_ssl_engine_fail()`) | `TLS13_WIPE` (fresh and resumed connection; it fails if either wipe is removed) |
| The tests prove little about a production build: the fuzzing build accepts what the fuzzer makes up | Refusals are tested on the production build: a bit flipped in every protected record in both directions and both places (ciphertext, tag), for the three suites with and without client authentication; a wrong Finished in each direction; a signature that does not verify (server, client) | `TLS13_TAMPER` (seen to fail with the tag check, the Finished check or the signature check removed) |
| The published coverage (87.2 %) is of the whole library | The TLS 1.3 C files are counted apart, with branches, and CI has floors (90 % of the lines, 65 % of the branches taken) | `sh test/coverage.sh`: 91.5 % and 69.3 % on 2026-11-22 |
| Nothing measured for the target: stack, RAM, record speed | `test/bench_resources.c`; CI prints it on aarch64, macOS arm64 and x86 32 bit | [testing.md](testing.md), "Memory and speed" |
| `br_tls13_expand_label` has fixed buffers and relies on its callers | `br_tls13_expand_label_checked()` checks every argument and returns 0; the old function calls it and fills the output with zero on an error; the label goes to the HMAC in pieces (no 255-byte copy) | `TLS13_KS` |
| The documents promised ECDSA P-521 and RSA-PSS/SHA-512 but the CertificateVerify check knew four schemes | The two schemes are implemented (the client offers `rsa_pss_rsae_sha512`) and run against OpenSSL, GnuTLS and Go: our server signs, our client verifies, our server verifies a client certificate (OpenSSL) | `interop_server13.sh`, 12 new cases (OpenSSL, GnuTLS, Go) |
| The interop script printed an error of the Go build and still succeeded; it stopped processes by name | It fails if Go is installed and does not build; `REQUIRE` names the peers that must be there; `EXPECT` checks the number of cases; it stops only its own processes by id | `sh test/interop_server13.sh` (46 cases) |
| The benchmark could print FAILED and exit 0 | It exits 1 | by reading |

**Four probes of `finished` that were left out of the gate until 2026-11-28** send a Finished message padded with 196 608 bytes and with about 16 MB. They failed now and then, and the cause was in our test server, not in the library. The server sends its one `decode_error` as soon as it sees the length, then reads what the client still sends. It stopped reading after 2000 reads or a pause of 2 s (before that, it did not read at all), and closed with data unread. The client's write then failed; tlsfuzzer takes a failed write as the alert's turn, skips reading the alert, and then rejects it as unexpected when it waits for the close. Seen on the old server: the two 16 MB probes failed in each of the runs made, with the drain ending at 2000 reads after 16 406 000 bytes; `strace` showed one alert written. The server now reads until the peer closes (its 300 s alarm bounds that), and the gate runs every probe of `finished` (`-n 0`: without it the script draws 40 of its probes at random). All 714 passed in 8 runs, 3 runs with the server and the client on one core, and the runs of the gate (Linux x86-64, 2026-11-28). The failures of the 196 608 byte probes were not reproduced afterwards (60 runs of the two, on a server that read up to the end).

### The reassessment of 2026-11-22

A second review of the release `0.6.1-tls13.0` plus the fixes, revision `1740f68` ([`SECURITY-REVIEW-2026-11-22.en.md`](../SECURITY-REVIEW-2026-11-22.en.md)), found the fixes above in place and named five things. What was done (2026-11-22; tests in `testcrypto` unless said otherwise):

| Finding | What was done | Test |
|---|---|---|
| 1. The expiry of tickets depends on a clock that the application may not give; the server accepted the exact 7 day boundary and the client refused at the lifetime; the bundled example gave no time | The server refuses at 7 days like the client; `br_ssl_engine_set_tls13_clock_required()` makes an engine without a clock skip tickets; `test/resume_client.c` sets the clock and requires it | `TLS13_SESSION` (the second before and at 7 days on the server, clock required and given, missing on the client, missing on the server) |
| 2. A policy number and an "authenticated" bit do not say who the client is | The SHA-256 of the client's certificate is kept with the session and restored on resumption (`br_ssl_engine_tls13_client_cert_hash()`); the guide says to keep a cache per trust domain or the domain in the policy identifier, and to change the identifier when a client is revoked | `TLS13_SESSION` (known after a full handshake and after a resumption, not known without authentication); revocation by policy: the policy test of the first review |
| 3. Forgetting a session left its secret in the cache | `br_ssl_session_cache_lru_forget()` overwrites the secret and the hash; `br_ssl_session_cache_lru_wipe()` overwrites the whole storage | `TLS13_CACHE` (seen to fail with the wipe removed) |
| 4. One error return skipped the wipe of the local copy of the shared secret | One exit for every path after the copy | by reading; the error cannot be made to happen in a test without a faulty hash table. The object code of the release was not inspected |
| 5. Alerts, the excluded probes, the interop harness | The interop script keeps and prints the logs of a failed case, waits for a port to listen instead of fixed pauses (three clean runs of the 46 cases afterwards; the earlier failures were not reproduced, so the cause is not known), and the exclusion of the four `finished` probes got an owner and an expiry date (the probes are back in the gate since 2026-11-28, see above); `style_check.sh` fails if a build file or the release workflow sets `BR_TLS13_FUZZ`; the refusal tests (`TLS13_TAMPER`) run on the build that is released | the scripts. **Not done then:** an alert for every TLS 1.3 error in both roles (done on 2026-11-27, see "Alerts for errors"); the 1.2 parser is not exercised apart from 1.3 |

The review also notes that RFC 9846 has replaced RFC 8446: a claim of conformance to the current specification needs a mapping to it. It was made on 2026-11-28; what it found, what was changed and what is still not met: [rfc9846.md](rfc9846.md). With those changes the tlsfuzzer scripts `legacy-version` and `keyshare-omitted` pass in full and are in the gate.

### Checked afterwards (2026-11-21, Linux x86-64, gcc 13.3, `vm.mmap_rnd_bits` 28)

- **Sanitizers**: the library built with AddressSanitizer and UndefinedBehaviorSanitizer (alignment check off, as in CI): `testcrypto all` and `testx509` pass; the interop script passes the 37 cases that do not need `resume_client` (that tool is not built with the sanitizers; the 9 cases that need it were not run in this build).
- **Fuzzing**: both targets of `test/fuzz` rebuilt from the fixed code and run for 10 minutes with 4 workers each (libFuzzer, ASan and UBSan, the crypto checks off as always): no crash, no timeout, no out-of-memory; about 440 000 and 560 000 executions in the longest worker, corpus of 3029 and 2669 files. The 24 hour runs of the first release are recorded in [testing.md](testing.md); the 24 hour run of the fixed code finished on 2026-11-22 with no artifact (see there).
- **Object code of the wipe**: for `br_ssl_server_tls13_psk_lookup` at `-O2`, gcc 13.3 left no wipe in the old code (after the copy of the PSK the function went straight to its end, as the review said); the new code calls `br_tls13_wipe()` on the success path and on the failure path, and that function is a loop of byte stores through a volatile pointer. Other functions were not looked at.
- **Timing of the padding**: removing the padding with the old loop took 1.4 ns with no padding and 4250 ns with 16 000 bytes of padding in a 16 401 byte record; `br_tls13_find_type()` took 9.57 µs for every padding (spread under 1 %). The price is about 0.6 ns per byte of the record, a few per cent of the AES-GCM time of a full record. A full `decrypt()` of a 4096 byte record with 0 to 4000 bytes of padding took the same time within 0.2 % (pinned core, no other load). The measurement is of the function, not of a remote attacker.
- **SHA-512 schemes with GnuTLS and Go**: ECDSA P-521 and RSA-PSS with SHA-512 (GnuTLS, forced with the priority string), P-521 with Go (a P-521 certificate can only be signed that way): our server and our client against each of them, 6 cases in `interop_server13.sh`. Go with an RSA key chooses RSA-PSS with SHA-256 and was not forced to SHA-512.

## Problems reported elsewhere, checked against our code

| Project and issue | Problem | Here |
|---|---|---|
| picotls [#605](https://github.com/h2o/picotls/issues/605) | A second HelloRetryRequest is not refused | Refused (`BR_ERR_UNEXPECTED`; test "hrr: a second one is refused" in `test/test_crypto.c`) (the alert is sent since 2026-11-27) |
| picotls #605, wolfSSL [#10016](https://github.com/wolfSSL/wolfssl/issues/10016) | The cipher suite of the ServerHello after a HelloRetryRequest is not compared with that of the HelloRetryRequest | Compared (`ssl_hs_client.t0`, "After a HelloRetryRequest the suite must be the same") |
| picotls #605 | The HelloRetryRequest asks for a group that the client already sent | Refused (`BR_ERR_BAD_PARAM`; test "hrr: same group as our share") |
| picotls #605 | Zero-length Handshake or Alert record accepted | Fixed above |
| picotls #605, [#594](https://github.com/h2o/picotls/issues/594) | Wrong alert for a bad Finished, a bad ChangeCipherSpec, a record that is too long, an empty Certificate | Bad Finished: fixed above. The others were closed without an alert; since 2026-11-27 an alert is sent ([Alerts for errors](#alerts-for-errors-2026-11-27)), but these cases were not looked at one by one |
| wolfSSL [#10320](https://github.com/wolfSSL/wolfssl/issues/10320), [#10321](https://github.com/wolfSSL/wolfssl/issues/10321) | An extension in the HelloRetryRequest or ServerHello that the client did not offer is accepted | Refused: the client reads extensions with a fixed list and fails on any other (`BR_ERR_EXTRA_EXTENSION`), with an alert since 2026-11-27 |
| wolfSSL [#10746](https://github.com/wolfSSL/wolfssl/issues/10746) | A HelloRetryRequest without `supported_versions`: wrong alert, and two alerts | Not tested here (by reading: the client sends one alert, the engine writes no second one) |
| wolfSSL [#10195](https://github.com/wolfSSL/wolfssl/issues/10195) | A server tells "no such PSK identity" from "wrong binder" | Does not apply as it was reported: an unknown ticket gives a full handshake, a wrong binder gives `decrypt_error`; a ticket is a random 32-byte identifier, so the difference tells an attacker nothing they can use. PSK-only mode does not exist here |
| wolfSSL [#10197](https://github.com/wolfSSL/wolfssl/issues/10197), rustls [#3311](https://github.com/rustls/rustls/issues/3311) | 0-RTT replay and early data with the wrong PSK | Does not apply: there is no 0-RTT |
| rustls [#3308](https://github.com/rustls/rustls/issues/3308), [#3310](https://github.com/rustls/rustls/issues/3310), [#2709](https://github.com/rustls/rustls/issues/2709) | A session of one policy is used with another; keys of long-lived connections are not changed | Fixed (see the next section): a policy identifier and the client-authentication state are stored with each session, and the engine changes its sending key before the limit of the cipher |
| rustls [#3313](https://github.com/rustls/rustls/pull/3313), [#3315](https://github.com/rustls/rustls/pull/3315) | Encrypting beyond the limits of the cipher; encrypting after a fatal alert | Not looked at (by reading: after it has failed the engine writes at most the one fatal alert, since 2026-11-27) |
| OpenSSL [#33460](https://github.com/openssl/openssl/issues/33460) | The all-zero check of X25519 skipped on one code path | We had no such check at all: fixed above |

## Ideas not taken, for later

- Run the same scripts against the client: tlsfuzzer has no client mode in the scripts used here; a client test needs a scripted server (the unit tests in `test/test_crypto.c` do this for HelloRetryRequest and the downgrade sentinel).
- BoringSSL and NSS as peers (named in the TLS working group list); wolfSSL and rustls as peers: not built or run.
- Open from the review: the ticket and the cache have no stateless form; the secrets that the application holds (the resumption secret in a saved `br_ssl_session_parameters`, the copies the application makes) are the application's to wipe; the handshake is written in T0 and has no line or branch figure; ARM, big-endian and 32-bit were not run on the laptop (no cross compiler, emulator or 32-bit libraries); the CI job `portability` runs them on other machines of GitHub (aarch64 and macOS on Apple silicon natively, x86 32 bit, and s390x in an emulator for the big-endian case, a subset of the tests there) and passes on the pull requests merged since; the object code was inspected for one function only (below).
- Keep the table of scripts that fail for a reason we accept in a file and make CI compare it, so that a script that starts to fail is noticed (today only the list `GATE` in `test/tlsfuzzer/run.sh` is checked).
