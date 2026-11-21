/*
 * Handshake speed: a client engine and a server engine in one process, a
 * full handshake and one record each way, many times; the CPU time of each
 * side is measured separately. ECDSA P-256 server key (and client key for
 * mutual authentication); the client validates the server certificate
 * with the X.509 engine.
 *
 *   cc -O2 -Isrc -Iinc -Itest/fuzz test/bench_handshake.c build/libbearssl.a \
 *       -o bench_handshake && ./bench_handshake [count]
 *
 * (With a library built without TLS 1.3 only the TLS 1.2 lines work; they are
 * skipped when BR_TLS13 is not defined.)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bearssl.h"
#include "fuzz_keys.h"

static double tc, ts;

static double
now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static unsigned char tmp[40000];

static void
move(br_ssl_engine_context *from, br_ssl_engine_context *to, double *tfrom,
	double *tto)
{
	unsigned char *b;
	size_t len, off = 0;
	double t0;

	b = br_ssl_engine_sendrec_buf(from, &len);
	if (b == NULL) {
		return;
	}
	/* copy first: the acknowledgement lets the engine reuse the buffer */
	memcpy(tmp, b, len);
	t0 = now();
	br_ssl_engine_sendrec_ack(from, len);
	*tfrom += now() - t0;
	b = tmp;
	while (off < len) {
		unsigned char *rb;
		size_t rl, n;

		rb = br_ssl_engine_recvrec_buf(to, &rl);
		if (rb == NULL) {
			fprintf(stderr, "stuck\n");
			exit(1);
		}
		n = len - off;
		if (n > rl) {
			n = rl;
		}
		memcpy(rb, b + off, n);
		t0 = now();
		br_ssl_engine_recvrec_ack(to, n);
		*tto += now() - t0;
		off += n;
	}
}

static unsigned char ta_dn[512];
static size_t ta_dn_len;

static void
dn_cb(void *ctx, const void *buf, size_t len)
{
	(void)ctx;
	if (ta_dn_len + len <= sizeof ta_dn) {
		memcpy(ta_dn + ta_dn_len, buf, len);
		ta_dn_len += len;
	}
}

static unsigned char ib1[BR_SSL_BUFSIZE_BIDI], ib2[BR_SSL_BUFSIZE_BIDI];
static br_ssl_client_context cc;
static br_ssl_server_context sc;
static br_x509_minimal_context cxc, sxc;

static int
run(const char *name, unsigned suite, unsigned vmax, int mtls, int count)
{
	br_x509_certificate chain[1];
	br_ec_private_key sk;
	br_x509_trust_anchor ta[1];
	br_x509_decoder_context dc;
	uint16_t suites[1];
	static const unsigned char seed[32] = { 3 };
	int i;
	double t_total;
	br_ssl_engine_context *ce = &cc.eng, *se = &sc.eng;

	suites[0] = (uint16_t)suite;
	chain[0].data = (unsigned char *)FUZZ_CERT;
	chain[0].data_len = sizeof FUZZ_CERT;
	sk.curve = BR_EC_secp256r1;
	sk.x = (unsigned char *)FUZZ_KEY;
	sk.xlen = sizeof FUZZ_KEY;
	ta_dn_len = 0;
	br_x509_decoder_init(&dc, dn_cb, NULL);
	br_x509_decoder_push(&dc, FUZZ_CERT, sizeof FUZZ_CERT);
	ta[0].pkey = *br_x509_decoder_get_pkey(&dc);
	/* the server certificate is self-signed: its subject is its issuer */
	ta[0].dn.data = ta_dn;
	ta[0].dn.len = ta_dn_len;
	ta[0].flags = BR_X509_TA_CA;

	tc = ts = 0;
	t_total = now();
	for (i = 0; i < count; i ++) {
		int step, sent_c = 0, sent_s = 0;
		double t0;

		t0 = now();
		br_ssl_client_init_full(&cc, &cxc, ta, 1);
		tc += now() - t0;
		t0 = now();
		br_ssl_server_init_full_ec(&sc, chain, 1, BR_KEYTYPE_EC, &sk);
		ts += now() - t0;
		br_x509_minimal_set_time(&cxc, 740303, 0);
		br_ssl_engine_set_versions(ce, BR_TLS12, vmax);
		br_ssl_engine_set_versions(se, BR_TLS12, vmax);
		br_ssl_engine_set_suites(ce, suites, 1);
		br_ssl_engine_set_suites(se, suites, 1);
		if (mtls) {
			br_x509_minimal_init(&sxc, &br_sha256_vtable, ta, 1);
			br_x509_minimal_set_hash(&sxc, br_sha256_ID,
				&br_sha256_vtable);
			br_x509_minimal_set_ecdsa(&sxc, br_ec_get_default(),
				br_ecdsa_vrfy_asn1_get_default());
			br_x509_minimal_set_time(&sxc, 740303, 0);
			br_ssl_client_set_single_ec(&cc, chain, 1, &sk,
				BR_KEYTYPE_SIGN, BR_KEYTYPE_EC,
				br_ec_get_default(),
				br_ecdsa_sign_asn1_get_default());
			br_ssl_server_set_trust_anchor_names_alt(&sc, ta, 1);
			br_ssl_engine_set_default_rsavrfy(se);
			br_ssl_engine_set_ecdsa(se,
				br_ecdsa_vrfy_asn1_get_default());
			br_ssl_engine_set_x509(se, &sxc.vtable);
		}
		br_ssl_engine_set_buffer(ce, ib1, sizeof ib1, 1);
		br_ssl_engine_set_buffer(se, ib2, sizeof ib2, 1);
		ce->rng_os_rand_done = 1;
		se->rng_os_rand_done = 1;
		br_ssl_engine_inject_entropy(ce, seed, 32);
		br_ssl_engine_inject_entropy(se, seed, 32);
		t0 = now();
		br_ssl_client_reset(&cc, "localhost", 0);
		tc += now() - t0;
		t0 = now();
		br_ssl_server_reset(&sc);
		ts += now() - t0;
		for (step = 0; step < 200; step ++) {
			int progress = 0;
			unsigned char *b;
			size_t len;

			if (br_ssl_engine_current_state(ce) & BR_SSL_SENDREC) {
				move(ce, se, &tc, &ts);
				progress = 1;
			}
			if (br_ssl_engine_current_state(se) & BR_SSL_SENDREC) {
				move(se, ce, &ts, &tc);
				progress = 1;
			}
			if (!sent_c && (br_ssl_engine_current_state(ce)
				& BR_SSL_SENDAPP))
			{
				b = br_ssl_engine_sendapp_buf(ce, &len);
				memset(b, 'c', 10);
				br_ssl_engine_sendapp_ack(ce, 10);
				br_ssl_engine_flush(ce, 0);
				sent_c = 1;
				progress = 1;
			}
			if (br_ssl_engine_current_state(se) & BR_SSL_RECVAPP) {
				b = br_ssl_engine_recvapp_buf(se, &len);
				br_ssl_engine_recvapp_ack(se, len);
				sent_s = 1;
				progress = 1;
			}
			if (!progress) {
				break;
			}
		}
		if (!sent_s || br_ssl_engine_last_error(ce) != 0
			|| br_ssl_engine_last_error(se) != 0)
		{
			printf("%-34s FAILED (client error %d, server error %d)\n",
				name, br_ssl_engine_last_error(ce),
				br_ssl_engine_last_error(se));
			return 1;
		}
		if (i == 0 && vmax == 0x0303 && ce->session.version != 0x0303) {
			printf("%-34s not TLS 1.2\n", name);
			return 1;
		}
	}
	t_total = now() - t_total;
	printf("%-34s client %6.3f ms  server %6.3f ms  total %6.3f ms per handshake\n",
		name, tc * 1000 / count, ts * 1000 / count, t_total * 1000 / count);
	return 0;
}

int
main(int argc, char **argv)
{
	int count = argc > 1 ? atoi(argv[1]) : 1000;
	int failed = 0;

	failed |= run("TLS 1.2 ECDHE-ECDSA AES-128-GCM", 0xC02B, 0x0303, 0, count);
	failed |= run("TLS 1.2 ECDHE-ECDSA ChaCha20", 0xCCA9, 0x0303, 0, count);
	failed |= run("TLS 1.2, client authentication", 0xC02B, 0x0303, 1, count);
#ifdef BR_TLS13
	failed |= run("TLS 1.3 AES-128-GCM", 0x1301, BR_TLS13, 0, count);
	failed |= run("TLS 1.3 AES-256-GCM", 0x1302, BR_TLS13, 0, count);
	failed |= run("TLS 1.3 ChaCha20", 0x1303, BR_TLS13, 0, count);
	failed |= run("TLS 1.3, client authentication", 0x1301, BR_TLS13, 1, count);
#endif
	return failed ? 1 : 0;
}
