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

A test of the client against the server cannot find a label that both sides get wrong; the independent peers below did that job.

## Interoperability (scripts in `test/`)

| Script | Cases | Result (2026-11-20) |
|---|---|---|
| `sh test/interop_openssl13.sh` (our client, OpenSSL server) | 14 | all pass |
| `sh test/interop_server13.sh` (our server and our client, against OpenSSL, GnuTLS and Go, including mutual TLS, HelloRetryRequest and resumption) | 31 | all pass, also under ASan + UBSan |

grpc-go v1.75.1 and nim-grpc, over TLS and mutual TLS: 21 cases (grpc-go client against nim-grpc server) and 18 cases (nim-grpc client against grpc-go server, with `--lenient-compression`) pass. nim-grpc's own 23 test programs pass on a scratch copy, and `tests/ttls.nim` 29 of 29 including resumption.

## Sanitizers

AddressSanitizer + UndefinedBehaviorSanitizer (alignment and function-type checks off; upstream loads unaligned words by design and fills its vtables with function pointer casts) on the unit tests and on the interop scripts: clean. An ASan binary built with an old libasan crashes at start now and then when `/proc/sys/vm/mmap_rnd_bits` is above 28; the runs here had it at 28 or checked it first. Alignment check: not run.

## Fuzzing

libFuzzer (clang 18, ASan + UBSan), client and server engines, build flag `BR_TLS13_FUZZ` (cryptographic checks off), seeds made by running a client and a server against each other (`test/fuzz`). A 10-minute trial run of about 4.5 million executions found no crash. The seed generator found a real bug (HelloRetryRequest with `renegotiation_info`), now fixed. **24-hour runs were started on 2026-11-20 on three machines and their result is not recorded here yet.** The gate "24 h without a finding" is not met until it is.

## Size and speed (2026-11-20, one machine)

| | upstream `7bea48e` | this fork |
|---|---|---|
| `libbearssl.a` | 1 027 992 B | 1 075 300 B |
| `client_basic` text (`-Os`, `--gc-sections`) | 116 625 B | 130 859 B (+12.2 %) |
| `server_basic` text | 111 839 B | 125 647 B (+12.3 %) |
| engine context | 3616 B | 5200 B |
| TLS 1.2 handshake, ECDHE-ECDSA-AES-128-GCM, 1000 runs | 1.334 ms | 1.334 ms |
| TLS 1.3 handshake, AES-128-GCM | not available | 1.086 ms (client 0.736, server 0.339) |
| TLS 1.2 with client authentication | 2.07 ms | 2.07 ms |
| TLS 1.3 with client authentication | not available | 1.833 ms |

Program: `test/bench_handshake.c`. Not measured: RSA keys, other machines, record throughput, memory use other than the context.

## Not run

`tlsfuzzer` and other conformance suites; non-OpenSSL HelloRetryRequest cookie; servers other than OpenSSL, GnuTLS, Go and grpc-go; timing-leak measurements; platforms other than Linux x86-64; builds with the alignment sanitizer; a byte-for-byte replay of the server side of RFC 8448 (the signature salt and the server random are random, so only the client side can be replayed).

## Documentation checks

`sh test/docs_check.sh` (2026-11-20): runs the README try-it and compares its output, compares the usage blocks of [reference-brssl.md](reference-brssl.md) with the program, compiles and runs the sample client and server with TLS 1.3, and checks that every link between the documents points to a file that exists.
