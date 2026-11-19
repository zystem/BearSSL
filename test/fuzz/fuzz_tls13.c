/*
 * libFuzzer targets for the TLS 1.3 handshake code of the client and of the
 * server engine.
 *
 * Build (see build.sh): the library is compiled with -DBR_TLS13_FUZZ, which
 * makes the TLS 1.3 record layer take the record body as plaintext (no AEAD,
 * so the fuzzer controls the inner content without knowing keys) and accepts
 * every CertificateVerify and Finished. This is for fuzzing only.
 *
 * Input: one configuration byte, then the bytes that the peer sends, which
 * are fed to the engine as the TCP stream in chunks of a size chosen by the
 * configuration byte. A record that is protected after the ServerHello
 * (outer type 23) is "decrypted" as is: its body is the inner plaintext
 * followed by the inner content type and the 16 bytes of tag.
 *
 *   FUZZ_CLIENT  the engine is a client (the input is what a server sends)
 *   FUZZ_SERVER  the engine is a server (the input is what a client sends)
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "bearssl.h"
#include "fuzz_keys.h"

#if !defined FUZZ_CLIENT && !defined FUZZ_SERVER
#error "define FUZZ_CLIENT or FUZZ_SERVER"
#endif

static const uint16_t SUITES[] = {
	0x1301, 0x1302, 0x1303,
	BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
};
static const char *PROTOS[] = { "h2", "http/1.1" };

static br_x509_certificate chain[1];
static br_ec_private_key sk;
static br_x509_trust_anchor ta[1];
static unsigned char ta_dn[512];
static size_t ta_dn_len;
static br_x509_decoder_context dec;
static int init_done;

static void
dn_cb(void *ctx, const void *buf, size_t len)
{
	(void)ctx;
	if (ta_dn_len + len <= sizeof ta_dn) {
		memcpy(ta_dn + ta_dn_len, buf, len);
		ta_dn_len += len;
	}
}

static void
init_once(void)
{
	br_x509_decoder_context d;
	const br_x509_pkey *pk;

	if (init_done) {
		return;
	}
	init_done = 1;
	chain[0].data = (unsigned char *)FUZZ_CERT;
	chain[0].data_len = sizeof FUZZ_CERT;
	sk.curve = BR_EC_secp256r1;
	sk.x = (unsigned char *)FUZZ_KEY;
	sk.xlen = sizeof FUZZ_KEY;

	/* Trust anchor: the certificate itself. */
	br_x509_decoder_init(&d, dn_cb, NULL);
	br_x509_decoder_push(&d, FUZZ_CERT, sizeof FUZZ_CERT);
	pk = br_x509_decoder_get_pkey(&d);
	ta[0].dn.data = ta_dn;
	ta[0].dn.len = ta_dn_len;
	ta[0].flags = BR_X509_TA_CA;
	ta[0].pkey = *pk;
	/* the key buffers point inside the decoder context: keep a copy */
	br_x509_decoder_init(&dec, NULL, NULL);
	br_x509_decoder_push(&dec, FUZZ_CERT, sizeof FUZZ_CERT);
	ta[0].pkey = *br_x509_decoder_get_pkey(&dec);
}

#ifdef FUZZ_CLIENT
static br_ssl_client_context cc;
#else
static br_ssl_server_context cc;
#endif
static br_x509_minimal_context xc;
static br_x509_knownkey_context kk;
static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];

static br_ssl_engine_context *
setup(uint8_t cfg)
{
	br_ssl_engine_context *eng;
	static const unsigned char seed[32] = { 1, 2, 3 };

#ifdef FUZZ_CLIENT
	br_ssl_client_init_full(&cc, &xc, ta, 1);
	eng = &cc.eng;
	if (cfg & 0x02) {
		br_ssl_client_set_single_ec(&cc, chain, 1, &sk,
			BR_KEYTYPE_SIGN, BR_KEYTYPE_EC,
			br_ec_get_default(), br_ecdsa_sign_asn1_get_default());
	}
#else
	br_ssl_server_init_full_ec(&cc, chain, 1, BR_KEYTYPE_EC, &sk);
	br_x509_minimal_init(&xc, &br_sha256_vtable, ta, 1);
	br_x509_minimal_set_hash(&xc, br_sha256_ID, &br_sha256_vtable);
	br_x509_minimal_set_hash(&xc, br_sha384_ID, &br_sha384_vtable);
	br_x509_minimal_set_ecdsa(&xc, br_ec_get_default(),
		br_ecdsa_vrfy_asn1_get_default());
	br_x509_minimal_set_rsa(&xc, br_rsa_pkcs1_vrfy_get_default());
	eng = &cc.eng;
	if (cfg & 0x02) {
		br_ssl_server_set_trust_anchor_names_alt(&cc, ta, 1);
		br_ssl_engine_set_default_rsavrfy(eng);
		br_ssl_engine_set_ecdsa(eng, br_ecdsa_vrfy_asn1_get_default());
	}
	br_ssl_engine_add_flags(eng, BR_OPT_TOLERATE_NO_CLIENT_AUTH & -(int)((cfg >> 2) & 1));
#endif
	br_x509_minimal_set_time(&xc, 740303, 0);
	if (cfg & 0x01) {
		/* the peer key is known: no chain validation */
		br_x509_knownkey_init_ec(&kk, &ta[0].pkey.key.ec, BR_KEYTYPE_SIGN);
		br_ssl_engine_set_x509(eng, &kk.vtable);
	} else {
#ifdef FUZZ_SERVER
		br_ssl_engine_set_x509(eng, &xc.vtable);
#endif
	}
	br_ssl_engine_set_versions(eng, (cfg & 0x08) ? BR_TLS12 : BR_TLS12,
		BR_TLS13);
	br_ssl_engine_set_suites(eng, SUITES, sizeof SUITES / sizeof SUITES[0]);
	br_ssl_engine_set_protocol_names(eng, PROTOS, 2);
	br_ssl_engine_set_buffer(eng, iobuf, sizeof iobuf, 1);
	eng->rng_os_rand_done = 1;
	br_ssl_engine_inject_entropy(eng, seed, sizeof seed);
#ifdef FUZZ_CLIENT
	br_ssl_client_reset(&cc, "localhost", 0);
#else
	br_ssl_server_reset(&cc);
#endif
	return eng;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	br_ssl_engine_context *eng;
	uint8_t cfg;
	size_t off, chunk, iter;
	int closed;

	if (len < 1) {
		return 0;
	}
	init_once();
	cfg = data[0];
	data ++;
	len --;
	switch ((cfg >> 4) & 3) {
	case 0: chunk = 100000; break;
	case 1: chunk = 1; break;
	case 2: chunk = 7; break;
	default: chunk = 200; break;
	}
	eng = setup(cfg);

	off = 0;
	closed = 0;
	for (iter = 0; iter < 100000; iter ++) {
		unsigned st;
		unsigned char *b;
		size_t blen;

		st = br_ssl_engine_current_state(eng);
		if (st & BR_SSL_CLOSED) {
			break;
		}
		if (st & BR_SSL_SENDREC) {
			b = br_ssl_engine_sendrec_buf(eng, &blen);
			if (b != NULL) {
				br_ssl_engine_sendrec_ack(eng, blen);
			}
			continue;
		}
		if (st & BR_SSL_RECVAPP) {
			b = br_ssl_engine_recvapp_buf(eng, &blen);
			if (b != NULL) {
				br_ssl_engine_recvapp_ack(eng, blen);
			}
			continue;
		}
		if ((st & BR_SSL_SENDAPP) && (cfg & 0x80)) {
			b = br_ssl_engine_sendapp_buf(eng, &blen);
			if (b != NULL && blen > 0) {
				memset(b, 'x', blen > 30 ? 30 : blen);
				br_ssl_engine_sendapp_ack(eng, blen > 30 ? 30 : blen);
				br_ssl_engine_flush(eng, 0);
				continue;
			}
		}
		if (st & BR_SSL_RECVREC) {
			size_t n;

			if (off >= len) {
				if (!closed) {
					br_ssl_engine_close(eng);
					closed = 1;
					continue;
				}
				break;
			}
			b = br_ssl_engine_recvrec_buf(eng, &blen);
			if (b == NULL) {
				break;
			}
			n = len - off;
			if (n > blen) {
				n = blen;
			}
			if (n > chunk) {
				n = chunk;
			}
			memcpy(b, data + off, n);
			br_ssl_engine_recvrec_ack(eng, n);
			off += n;
			continue;
		}
		break;
	}
	return 0;
}
