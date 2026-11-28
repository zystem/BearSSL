# What was run

*Kind: record.* What was run on what, and what was not. Dates are 2026; "not run" means exactly that. Details per step are in [TLS13-PLAN.md](../TLS13-PLAN.md).

## Environment

Linux 6.8 x86-64, gcc 13.3 and clang 18, OpenSSL 3.0.13, GnuTLS (`gnutls-cli`/`gnutls-serv`), Go 1.24, grpc-go v1.75.1, nim-grpc 0.7.0, nim-bearssl 0.3.1.

## Unit tests (`build/testcrypto`, `build/testx509`)

| Test | Checks | Run |
|---|---|---|
| `TLS13_KS` | key schedule against the RFC 8448 simple trace (SHA-256 only: the RFC has no SHA-384 trace) | 2026-11-17 and with every later change |
| `TLS13_REC` | record protection: AES-128-GCM against RFC 8448; AES-256-GCM and ChaCha20-Poly1305 against an independent Python implementation | same |
| `TLS13_HS`, `TLS13_REPLAY` | client handshake against RFC 8448 (client side replayed byte for byte) | same |
| `TLS13_HRR` | RFC 8448 HelloRetryRequest trace, refusals, downgrade sentinels | same |
| `TLS13_LOOPBACK` | client against server in one process: 3 suites, with and without client authentication, with HelloRetryRequest, resumption (full, resumed, resumed again, forgotten ticket, wrong PSK) | same |
| `TLS13_ALERTS` | the alert that an engine sends for an error, in both roles, before and after the keys; none without TLS 1.3; the state while the alert waits; a KeyUpdate in pieces, with data in the middle, twice in one record, with a bad value; since 2026-11-28 also the level of a received alert, ClientHello messages that must be refused, messages after a ServerHello or a Finished in the same record, extensions out of place, the minimum version of the full profiles, ChangeCipherSpec records (when they are dropped and refused, also after a reset) and an empty list of signature algorithms | 2026-11-27 |

A test of the client against the server cannot find a label that both sides get wrong; the independent peers below did that job.

## Interoperability (scripts in `test/`)

| Script | Cases | Result (2026-11-20) |
|---|---|---|
| `sh test/interop_openssl13.sh` (our client, OpenSSL server) | 14 | all pass |
| `sh test/interop_server13.sh` (our server and our client, against OpenSSL, GnuTLS and Go, including mutual TLS, HelloRetryRequest and resumption) | 31 | all pass, also under ASan + UBSan |

grpc-go v1.75.1 and nim-grpc, over TLS and mutual TLS: 21 cases (grpc-go client against nim-grpc server) and 18 cases (nim-grpc client against grpc-go server, with `--lenient-compression`) pass. nim-grpc's own 23 test programs pass on a scratch copy, and `tests/ttls.nim` 29 of 29 including resumption.

## Coverage and style

`sh test/coverage.sh` builds with `--coverage`, runs `testcrypto all`, `testx509` and the interoperability scripts (the peers that are installed), and adds up the lines of `src/` that gcov reports and the lines and branches of the TLS 1.3 C files (`ssl_tls13_*.c`, `ssl_rec13_*.c`); the CI job `coverage` fails below 80 % of the lines of `src/`, 90 % of the lines of the TLS 1.3 C files and 65 % of their branches taken at least once. Run on 2026-11-22 (with OpenSSL, GnuTLS and Go): 87.8 % of `src/`, 91.5 % of the 745 lines of the TLS 1.3 C files, 69.3 % of their 345 branches (most of the rest are refusals of impossible arguments). The handshake is written in T0 and gcov cannot see into the table that the T0 compiler makes: those paths are covered by the loopback, tamper, session and HelloRetryRequest tests and by the interop scripts, not by a number. Run by hand on 2026-11-20 (gcc 13, Linux x86-64, 3 min 37 s): 17798 of 20409 lines, **87.2 %**. This is line coverage of the whole of `src/`, upstream's code included; the files with no coverage are the ones nothing here uses (for example PEM encoding, CBC and CCM records, the RSA single-key handlers). Branch coverage was not measured. The interoperability script with GnuTLS and Go (`test/interop_server13.sh`) is not part of this number.

The X.509 test vectors of `test/x509` are text (a PEM-like block with Base64; `read_file` in `test/test_x509.c` decodes them); `build/testx509` printed the same 55 lines with the text vectors as with the binary ones (checked 2026-11-20).

`sh test/style_check.sh` checks that no binary file is tracked in the repository, and tabs, trailing white space and the line length of the C files the fork added (CI step "Coding standard"); run on 2026-11-20: ok.

## After the fixes of 2026-11-21

Run on 2026-11-21 after the fixes in [conformance.md](conformance.md): `testcrypto all` and `testx509` also under AddressSanitizer + UndefinedBehaviorSanitizer (exit 0); both fuzz targets for 10 minutes with 4 workers each (no artifact); `sh test/interop_server13.sh`, 46 cases with OpenSSL, GnuTLS and Go; `sh test/tlsfuzzer/run.sh`.

## Memory and speed

`test/bench_resources.c` prints the sizes of the contexts, the stack of the deepest call of a handshake, and the speed of the record layer (the CI job `portability` prints the same on the other machines of GitHub; its output is not checked). Run on 2026-11-22 on the laptop (Linux x86-64, 13th Gen Intel Core i9, gcc 13.3, library at `-Os`, the program at `-O2`, one core, no other load):

```bash
cc -O2 -Isrc -Iinc -Itest/fuzz test/bench_resources.c build/libbearssl.a -pthread -o bench_resources && taskset -c 3 ./bench_resources
```

```text
Sizes (bytes)
  br_ssl_engine_context              6024
  br_ssl_client_context              6128
  br_ssl_server_context              6536
  br_x509_minimal_context            3176
  br_ssl_session_parameters           620
  BR_SSL_BUFSIZE_BIDI (two buffers) 33178   BR_SSL_BUFSIZE_MONO 16709
  a client: context + X.509 + both buffers: 42482
Stack of the deepest call of a handshake (one engine)
  TLS 1.2 ECDHE-ECDSA AES-128-GCM     11760 bytes of stack
  TLS 1.3 AES-128-GCM                 11888 bytes of stack
  TLS 1.3 AES-256-GCM                 11888 bytes of stack
  TLS 1.3 ChaCha20-Poly1305           11888 bytes of stack
  TLS 1.3, client authentication      11888 bytes of stack
Records
  AES-128-GCM (ct64)      1024 byte records:    39.4 MB/s (protect + unprotect)
  AES-128-GCM (ct64)     16384 byte records:    47.7 MB/s (protect + unprotect)
  AES-256-GCM (ct64)     16384 byte records:    39.8 MB/s (protect + unprotect)
  ChaCha20-Poly1305       1024 byte records:   139.2 MB/s (protect + unprotect)
  ChaCha20-Poly1305      16384 byte records:   159.5 MB/s (protect + unprotect)
```

The figures above are of the revision of that day; the contexts have grown since (6208, 6312 and 6720 bytes for the engine, client and server contexts: the hash of the client certificate and a SHA-256 context were added). What it shows: TLS 1.3 needs about 130 bytes more stack than TLS 1.2 for the deepest call (the figure includes the frames of the test program, under 1 KiB), and the engine context is larger by the TLS 1.3 state (the resumption ticket, the secrets, the counters). The record speed is that of the constant-time software AES (`aes_ct64`, the portable default) and of the portable ChaCha20; AES-NI and the CLMUL hash would be faster and are not used here (the program selects the portable code on purpose, so that the figures can be compared with other machines). The text sizes of the TLS 1.3 files at `-Os`: `ssl_tls13_hs.o` 8857 bytes, `ssl_tls13_ks.o` 1981, `ssl_rec13_gcm.o` 1554, `ssl_rec13_chapol.o` 983, and the generated handshake `ssl_hs_client.o` 13 526 and `ssl_hs_server.o` 14 198 (both include TLS 1.2). **Not measured**: the stack with RSA keys or with the whole chain validation of a long chain, the memory of a server with many connections, a gRPC stream with key updates, speed on an ARM or embedded core (only printed by CI), and the time of a resumption handshake.

## Sanitizers

AddressSanitizer + UndefinedBehaviorSanitizer (alignment and function-type checks off; upstream loads unaligned words by design and fills its vtables with function pointer casts) on the unit tests and on the interop scripts: clean. An ASan binary built with an old libasan crashes at start now and then when `/proc/sys/vm/mmap_rnd_bits` is above 28; the runs here had it at 28 or checked it first. Alignment check: not run.

Run on 2026-11-27 after the alerts for TLS 1.3 errors ([conformance.md](conformance.md)), Linux x86-64: `testcrypto all` and `testx509`, also under AddressSanitizer + UndefinedBehaviorSanitizer (clang 18, exit 0); `interop_openssl13.sh`; `interop_server13.sh`, 46 cases; `tlsfuzzer/run.sh` three times (ok); both fuzz targets for 2 minutes with 4 workers each (no artifact).

Run on 2026-11-28 after the changes for [RFC 9846](rfc9846.md), Linux x86-64: `testcrypto all` and `testx509`, also under AddressSanitizer + UndefinedBehaviorSanitizer (clang 18, exit 0); the new checks of `TLS13_ALERTS` were seen to fail with each of five changes taken out; `interop_openssl13.sh`; `interop_server13.sh`, 46 cases; `tlsfuzzer/run.sh` three times (ok); all 57 tlsfuzzer scripts, 2162 probes passed and 765 failed (2149 and 778 on `master` the same day; the totals vary between runs, see [conformance.md](conformance.md)); both fuzz targets for 2 minutes with 4 workers each (no artifact). Not run: the client against tlsfuzzer; a long fuzz run of this code.

Run on 2026-11-28 after the changes to ChangeCipherSpec, record versions and the empty list ([conformance.md](conformance.md)), Linux x86-64: `testcrypto all` and `testx509`, also under AddressSanitizer + UndefinedBehaviorSanitizer (clang 18, exit 0); the new checks were seen to fail with each of five changes taken out; `interop_openssl13.sh`; `interop_server13.sh`, 46 cases; `tlsfuzzer/run.sh` three times (ok); both fuzz targets for 2 minutes with 4 workers each (no artifact).

## Fuzzing

libFuzzer (clang 18, ASan + UBSan), client and server engines, build flag `BR_TLS13_FUZZ` (cryptographic checks off), seeds made by running a client and a server against each other (`test/fuzz`). A 10-minute trial run of about 4.5 million executions found no crash. The seed generator found a real bug (HelloRetryRequest with `renegotiation_info`), now fixed. **The 24 hour runs of 2026-11-20 and what they were** (read on 2026-11-21 16:00 from the machines; code of commit `e7a3fe6` for the first two and `f08786e` for the third, both before the fixes of [conformance.md](conformance.md)):

| Machine | Target | Run | Result |
|---|---|---|---|
| 192.168.100.77 | server, 2 workers | finished: 86 401 s | 15 530 581 runs in one worker's log; **no artifact** |
| 192.168.100.4 (hypervisor, `nice 19`) | client and server, 8 workers each | both finished: 86 401 s | all 8 jobs of each exited with code 0; **no artifact**. The two targets ran in one directory and wrote the same worker log files, so the numbers of runs cannot be given per target (a figure per target that this table had until 2026-11-26 was taken from those files and is withdrawn) |
| 192.168.100.85 | client, 2 workers | **stopped after about 18.8 hours**: the machine restarted (boot at 21:41 on 2026-11-20; the logs end at 19:02 and 19:08, the cause was not found) | about 10.3 and 12.5 million runs in the two workers' last lines; **no artifact**; the 24 hours were not reached |

So the gate "24 h without a finding" is met for the server (two machines) and for the client on the hypervisor (code `f08786e`); the client run of the first machine is short of 24 hours. These runs are of code that is older than the fixes of 2026-11-21.

**The 24 hour run of commit `0fa53ee`** (read on 2026-11-26; it finished after release `v0.6.1-tls13.1` was made): 192.168.100.4 (Xeon E5-2673 v3, 24 threads), both targets at the same time, 8 workers each, `nice 19`, binaries built with clang 18, from 2026-11-21 16:03 to 2026-11-22 16:03 (+02:00). All 8 jobs of each target exited with code 0 after 86 401 s, **no artifact** (no crash, timeout or out-of-memory file); the corpora ended with 16 388 (client) and 20 788 (server) files. As in the run before, the two targets wrote the same worker log files, so there is no number of runs per target (the surviving worker logs end between 9.5 and 13.5 million runs each). `test/fuzz/run.sh` gives each target its own log directory; these two runs were started with another script that did not.

**This is not the code of release `v0.6.1-tls13.1`.** The release also has commit `8af7ae2`, made after `0fa53ee`: it wipes the secrets when the handshake is over (`src/ssl/ssl_tls13_hs.c`, `src/ssl/ssl_engine.c`, `src/inner.h`). Neither this run nor the 10 minute run covered that change, and the fixes of the reassessment of 2026-11-22 ([conformance.md](conformance.md)) are newer still. (Until 2026-11-26 this page said that `0fa53ee` was the code of the release; that was wrong.)

The same commit `8af7ae2` broke the seed generator (`test/fuzz/mkseeds.sh` stopped with "cannot open a record", because it read the handshake secrets after the engine had wiped them), so the weekly `fuzz.yml` run of 2026-11-22 failed before it fuzzed. Fixed on 2026-11-26; the CI job `build` now makes the seeds, so a pull request that breaks them fails.

**The two 24 hour runs of 2026-11-26 to 28** (read on 2026-11-28), 192.168.100.4 (24 threads, a hypervisor with virtual machines running), `test/fuzz/run.sh` (each target has its own logs), both targets at the same time, `nice 19`, 86 400 s each:

| Code of `src`, `inc` | Workers per target | From, to (+02:00) | Target | Runs, all workers | Corpus at the end | Coverage (`cov` / `ft`) | Artifacts |
|---|---|---|---|---|---|---|---|
| `23a719e` (without the alerts) | 8 | 2026-11-26 23:32 to 11-27 23:32 | client | 61 633 090 | 17 755 | 1259 / 4138 | **none** |
| | | | server | 77 989 659 | 23 279 | 1251 / 4084 | **none** |
| `beea7d3` (with the alerts) | 4 | 2026-11-27 02:03 to 11-28 02:03 | client | 38 857 648 | 17 615 | 1301 / 4186 | **none** |
| | | | server | 37 483 359 | 22 381 | 1286 / 4143 | **none** |

All workers of both runs ran their full time; no line of a sanitizer error is in their logs. The first run began with 16 new seeds per target and the corpus of the run of `0fa53ee`; the second with 16 new seeds and a copy of the first one's corpus, taken while it ran. From 02:03 to 23:32 on 2026-11-27 the two runs shared the machine (24 workers on 24 threads, beside the virtual machines). The coverage figures are of different code and do not compare.

**Neither run covers the changes of 2026-11-28** ([rfc9846.md](rfc9846.md): alert levels, record boundaries, checks of the ClientHello and of extensions); those, and the ChangeCipherSpec changes made later that day, had 2 minutes of fuzzing (above).

## Size and speed (2026-11-20, one machine)

| | upstream `7bea48e` | this fork |
|---|---|---|
| `libbearssl.a` | 1 027 992 B | 1 075 300 B |
| `client_basic` text (`-Os`, `--gc-sections`) | 116 625 B | 130 859 B (+12.2 %) |
| `server_basic` text | 111 839 B | 125 647 B (+12.3 %) |
| engine context | 3616 B | 6208 B (6024 B in `0.6.1-tls13.1`) |
| TLS 1.2 handshake, ECDHE-ECDSA-AES-128-GCM, 1000 runs | 1.334 ms | 1.334 ms |
| TLS 1.3 handshake, AES-128-GCM | not available | 1.086 ms (client 0.736, server 0.339) |
| TLS 1.2 with client authentication | 2.07 ms | 2.07 ms |
| TLS 1.3 with client authentication | not available | 1.833 ms |

Program: `test/bench_handshake.c`. Not measured: RSA keys, other machines, record throughput, memory use other than the context.

## Not run

`tlsfuzzer` against the client and conformance suites other than `tlsfuzzer`; non-OpenSSL HelloRetryRequest cookie; servers other than OpenSSL, GnuTLS, Go and grpc-go; timing-leak measurements; platforms other than Linux x86-64; builds with the alignment sanitizer; a byte-for-byte replay of the server side of RFC 8448 (the signature salt and the server random are random, so only the client side can be replayed).

## Documentation checks

`sh test/docs_check.sh` (2026-11-20): runs the README try-it and compares its output, compares the usage blocks of [reference-brssl.md](reference-brssl.md) with the program, compiles and runs the sample client and server with TLS 1.3, and checks that every link between the documents points to a file that exists.

## Continuous integration

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (jobs `build` with gcc and clang and `-Werror`, `sanitizers`, `interop`, `t0`), `codeql.yml`, `dco.yml`, `dependency-review.yml`, `scorecard.yml`, `fuzz.yml` and `release.yml` were written on 2026-11-20. They have run on GitHub since 2026-11-20: `build` (gcc, clang), `sanitizers`, `t0`, CodeQL (`Analyze (c-cpp)`), `dco` and `dependency-review` passed on the pull requests that are now merged, and the release workflow passed on the tag `v0.6.1-tls13.0`. What was run by hand, with the same commands, on a copy of the tree (2026-11-20, Linux x86-64, gcc 13, clang 18): the build with `-W -Wall -Werror` with both compilers (no warning); `testcrypto all` and `testx509` normal and under AddressSanitizer + UndefinedBehaviorSanitizer (exit 0); `sh test/docs_check.sh` (205 checks, 0 failures); `sh test/interop_openssl13.sh`; `make T0` with no change in `src`; seeds, fuzz build and a 20 s run of both targets (0 artifacts). Not seen yet: a Scorecard result and a run of the weekly `fuzz.yml`.
