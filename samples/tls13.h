/*
 * Enable TLS 1.3 in a context made by one of the br_ssl_client_init_*() or
 * br_ssl_server_init_*() profiles. The profiles stop at TLS 1.2 (so that
 * programs built before this fork behave as before); a program opts in.
 *
 * Call it after the profile function and before the first handshake
 * (before br_ssl_client_reset() or br_ssl_server_reset()).
 *
 * Needs a profile that has SHA-256 and SHA-384 (the "full" profiles have
 * all hash functions) and AES-GCM or ChaCha20+Poly1305 (the "full"
 * profiles have both). The server's policy handler must have the choose13
 * and do_sign13 methods (the handlers of this library, single_rsa and
 * single_ec, have them).
 */
#ifndef SAMPLES_TLS13_H__
#define SAMPLES_TLS13_H__

#include "bearssl.h"

static void
sample_enable_tls13(br_ssl_engine_context *eng)
{
	/*
	 * TLS 1.3 suites first, then TLS 1.2 suites for peers that do not
	 * speak TLS 1.3. Remove the TLS 1.2 suites and raise the minimum
	 * version to BR_TLS13 to refuse older peers.
	 */
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
	br_ssl_engine_set_suites(eng, suites,
		(sizeof suites) / (sizeof suites[0]));
}

#endif
