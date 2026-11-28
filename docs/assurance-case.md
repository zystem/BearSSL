# Assurance case: why the design is believed secure enough, and where it is not

*Kind: explanation.* The argument in one place: the claim, the threats it is set against, the design principles that answer them, the common weaknesses of C code and what is done about each, and what is not shown. It builds on [threat-model.md](threat-model.md) (who attacks and what is protected) and [explanation-security-status.md](explanation-security-status.md) (what is known). **Nobody outside the project has reviewed this argument.**

## Claim

A program that uses this library as [production-checklist.md](production-checklist.md) says gets a TLS 1.3 connection in which a network attacker can neither read nor change the data, nor make the two sides agree on a lower version unnoticed, nor impersonate a peer whose certificate chain the application trusts. This holds only to the extent the tests, the tools and the review of the author found no fault; it is not a proof.

## Trust boundaries

| Boundary | Inside | Outside (not trusted) |
|---|---|---|
| The network | the engine (`br_ssl_engine_context`) | every byte read from the socket |
| The application | the context it owns, the policy handler, the trust anchors | the application must seed the PRNG and choose trust anchors ([reference-api.md](reference-api.md)) |
| The build | the sources in this repository, the committed generated handshake code | compiler, Mono (T0), the runner |
| The release | the files signed by the release workflow | anything else claiming to be a release ([verifying-releases.md](verifying-releases.md)) |

## Secure design principles

| Principle | How the library follows it | Where it does not |
|---|---|---|
| Economy of mechanism | a small code base; one state machine written in T0 ([explanation-design.md](explanation-design.md)); no features such as 0-RTT that enlarge the attack surface | the fork adds a second handshake to the code base |
| Fail-safe defaults | TLS 1.3 is off unless the program asks; a policy handler without `choose13` stops the handshake; an unknown or misplaced message ends the connection with an alert | none known |
| Complete mediation | every record goes through the record layer, which checks length, tag and type; every handshake message goes through the one state machine | none known |
| Open design | the sources, the tests, the threat model and this page are public | none |
| Separation of privilege / least privilege | the library opens no files and no sockets and holds no global state; the application owns all I/O and keys | the application context holds the secrets for the whole connection, and is not wiped at the end ([threat-model.md](threat-model.md)) |
| Least common mechanism | no shared mutable global state; the session cache is the application's object | the cache is shared by connections when the application shares it |
| Psychological acceptability | one call turns TLS 1.3 on; the documents say what to do ([howto-enable-tls13.md](howto-enable-tls13.md)) | the API is upstream's and has sharp edges |

## Common weaknesses of C code and of TLS, and what answers them

| Weakness | What answers it | How it is checked |
|---|---|---|
| Buffer overflow, out-of-bounds read (CWE-119, CWE-125) | no `malloc`, fixed-size buffers with explicit bounds, lengths of every message checked before use, no recursion | AddressSanitizer on the unit and interoperability tests; libFuzzer targets for client and server; CodeQL |
| Integer overflow (CWE-190) | lengths are checked against the record limit (16 KiB plus the protection overhead) and the buffer size before use | UndefinedBehaviorSanitizer; fuzzing |
| Timing and cache side channels (CWE-208) | constant-time primitives (upstream); no branch or table index on a secret in the new code, by rule ([../CONTRIBUTING.md](../CONTRIBUTING.md)); binder and Finished compared in constant time | **reviewed, not measured** |
| Invalid input accepted (CWE-20) | strict parsers: a length that does not fit its buffer or a message at the wrong time is an error (`BR_ERR_UNEXPECTED` and the other `BR_ERR_*` codes) | RFC 8448 traces and refusal tests; fuzzing with seeds from real handshakes |
| Downgrade to an older version | the `DOWNGRD` sentinel in the server random, checked by the client; the supported-versions extension is mandatory in TLS 1.3 | `TLS13_HRR` test and interoperability |
| Wrong key schedule label (a fault both sides share) | independent peers: OpenSSL, GnuTLS, Go | interoperability scripts ([testing.md](testing.md)) |
| Replay of tickets | no 0-RTT, so a replay reaches no early data | stated, not tested further |
| Use of a weak or no random source | the application seeds the PRNG (`br_ssl_engine_inject_entropy()` or the system source); an unseeded PRNG gives `BR_ERR_NO_RANDOM` | [production-checklist.md](production-checklist.md) (not run with TLS 1.3) |
| Vulnerable dependency | there is no external code in the library; the test tools use Go modules, watched by Dependabot and Dependency Review ([security-policies.md](security-policies.md)) | CI |
| Tampered release | one workflow builds, signs and attests it | [verifying-releases.md](verifying-releases.md) |

## Hardening

- **In the design**: no heap, no global state, fixed buffers, a strict state machine, constant-time primitives.
- **In the build**: compiled with `-W -Wall -Werror` by two compilers in CI; with AddressSanitizer and UndefinedBehaviorSanitizer in CI.
- **Not done**: the default `make` does not add compiler hardening flags (stack protector, `_FORTIFY_SOURCE`, position-independent executables for the tool) because this is a library that the application builds with its own flags; a program that links it should use its own hardening flags.

## What is not shown

No independent audit; side channels of the new code not measured; no formal analysis of the handshake; the fuzz runs were not finished at the first and second release, and the changes of 2026-11-28 have no 24 hour run. See [threat-model.md](threat-model.md), "Not covered, or not known".
