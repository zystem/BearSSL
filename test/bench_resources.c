/*
 * What a TLS 1.3 connection costs in memory, and how fast the record layer
 * is: the sizes of the contexts and of the buffers, the stack that the
 * deepest call of a handshake uses (a client and a server engine in one
 * thread; they are never on the stack together, so the figure is for one
 * engine), the code size of the TLS 1.3 files, and the speed of protecting
 * and unprotecting records of 1 KiB and 16 KiB with each cipher.
 *
 *   cc -O2 -Isrc -Iinc -Itest/fuzz test/bench_resources.c build/libbearssl.a \
 *       -pthread -o bench_resources && ./bench_resources
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "bearssl.h"
#include "inner.h"
#include "fuzz_keys.h"

static double
now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static unsigned char tmp[40000];

static void
move(br_ssl_engine_context *from, br_ssl_engine_context *to)
{
	unsigned char *b;
	size_t len, off = 0;

	b = br_ssl_engine_sendrec_buf(from, &len);
	if (b == NULL) {
		return;
	}
	memcpy(tmp, b, len);
	br_ssl_engine_sendrec_ack(from, len);
	while (off < len) {
		unsigned char *rb;
		size_t rl, n;

		rb = br_ssl_engine_recvrec_buf(to, &rl);
		if (rb == NULL) {
			break;
		}
		n = len - off;
		if (n > rl) {
			n = rl;
		}
		memcpy(rb, tmp + off, n);
		br_ssl_engine_recvrec_ack(to, n);
		off += n;
	}
}

static br_ssl_client_context cc;
static br_ssl_server_context sc;
static br_x509_minimal_context cxc, sxc;
static unsigned char ib1[BR_SSL_BUFSIZE_BIDI], ib2[BR_SSL_BUFSIZE_BIDI];
static unsigned char ta_dn[512];
static size_t ta_dn_len;

static void
dn_cb(void *ctx, const void *buf, size_t len)
{
	(void)ctx;
	memcpy(ta_dn + ta_dn_len, buf, len);
	ta_dn_len += len;
}

typedef struct {
	unsigned suite, vmax;
	int mtls;
	int ok;
} job;

/* a full handshake and one record each way */
static void *
handshake(void *arg)
{
	job *j = arg;
	br_x509_certificate chain[1];
	br_ec_private_key sk;
	br_x509_trust_anchor ta[1];
	br_x509_decoder_context dc;
	uint16_t suites[1];
	static const unsigned char seed[32] = { 3 };
	br_ssl_engine_context *ce = &cc.eng, *se = &sc.eng;
	int step, sent_c = 0, got = 0;

	suites[0] = (uint16_t)j->suite;
	chain[0].data = (unsigned char *)FUZZ_CERT;
	chain[0].data_len = sizeof FUZZ_CERT;
	sk.curve = BR_EC_secp256r1;
	sk.x = (unsigned char *)FUZZ_KEY;
	sk.xlen = sizeof FUZZ_KEY;
	ta_dn_len = 0;
	br_x509_decoder_init(&dc, dn_cb, NULL);
	br_x509_decoder_push(&dc, FUZZ_CERT, sizeof FUZZ_CERT);
	ta[0].pkey = *br_x509_decoder_get_pkey(&dc);
	ta[0].dn.data = ta_dn;
	ta[0].dn.len = ta_dn_len;
	ta[0].flags = BR_X509_TA_CA;
	br_ssl_client_init_full(&cc, &cxc, ta, 1);
	br_ssl_server_init_full_ec(&sc, chain, 1, BR_KEYTYPE_EC, &sk);
	br_x509_minimal_set_time(&cxc, 740303, 0);
	br_ssl_engine_set_versions(ce, BR_TLS12, j->vmax);
	br_ssl_engine_set_versions(se, BR_TLS12, j->vmax);
	br_ssl_engine_set_suites(ce, suites, 1);
	br_ssl_engine_set_suites(se, suites, 1);
	if (j->mtls) {
		br_x509_minimal_init(&sxc, &br_sha256_vtable, ta, 1);
		br_x509_minimal_set_hash(&sxc, br_sha256_ID, &br_sha256_vtable);
		br_x509_minimal_set_ecdsa(&sxc, br_ec_get_default(),
			br_ecdsa_vrfy_asn1_get_default());
		br_x509_minimal_set_time(&sxc, 740303, 0);
		br_ssl_client_set_single_ec(&cc, chain, 1, &sk, BR_KEYTYPE_SIGN,
			BR_KEYTYPE_EC, br_ec_get_default(),
			br_ecdsa_sign_asn1_get_default());
		br_ssl_server_set_trust_anchor_names_alt(&sc, ta, 1);
		br_ssl_engine_set_default_rsavrfy(se);
		br_ssl_engine_set_ecdsa(se, br_ecdsa_vrfy_asn1_get_default());
		br_ssl_engine_set_x509(se, &sxc.vtable);
	}
	br_ssl_engine_set_buffer(ce, ib1, sizeof ib1, 1);
	br_ssl_engine_set_buffer(se, ib2, sizeof ib2, 1);
	ce->rng_os_rand_done = 1;
	se->rng_os_rand_done = 1;
	br_ssl_engine_inject_entropy(ce, seed, 32);
	br_ssl_engine_inject_entropy(se, seed, 32);
	br_ssl_client_reset(&cc, "localhost", 0);
	br_ssl_server_reset(&sc);
	for (step = 0; step < 200; step ++) {
		int progress = 0;
		unsigned char *b;
		size_t len;

		if (br_ssl_engine_current_state(ce) & BR_SSL_SENDREC) {
			move(ce, se);
			progress = 1;
		}
		if (br_ssl_engine_current_state(se) & BR_SSL_SENDREC) {
			move(se, ce);
			progress = 1;
		}
		if (!sent_c && (br_ssl_engine_current_state(ce) & BR_SSL_SENDAPP)) {
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
			got = 1;
			progress = 1;
		}
		if (!progress) {
			break;
		}
	}
	j->ok = got && br_ssl_engine_last_error(ce) == 0
		&& br_ssl_engine_last_error(se) == 0;
	return NULL;
}

#define STACK_SIZE   (512 * 1024)

/* the deepest use of the stack: paint it, run, look for what was touched */
static void
stack_use(const char *name, unsigned suite, unsigned vmax, int mtls)
{
	pthread_attr_t at;
	pthread_t th;
	unsigned char *stk;
	job j;
	size_t u;

	stk = malloc(STACK_SIZE);
	memset(stk, 0xA5, STACK_SIZE);
	pthread_attr_init(&at);
	pthread_attr_setstack(&at, stk, STACK_SIZE);
	j.suite = suite;
	j.vmax = vmax;
	j.mtls = mtls;
	j.ok = 0;
	pthread_create(&th, &at, &handshake, &j);
	pthread_join(th, NULL);
	/* the stack grows down: the lowest address that was written */
	for (u = 0; u < STACK_SIZE && stk[u] == 0xA5; u ++);
	printf("  %-34s %6zu bytes of stack%s\n", name, STACK_SIZE - u,
		j.ok ? "" : "  (the handshake FAILED)");
	free(stk);
	if (!j.ok) {
		exit(1);
	}
}

/* record protection speed */
static void
records(const char *name, int is_gcm, size_t key_len, size_t rec_len)
{
	static unsigned char buf[16384 + 64], rec[16384 + 64];
	static br_sslrec13_gcm_context og, ig;
	static br_sslrec13_chapol_context oc, ic;
	unsigned char key[32], iv[12];
	int count = (int)(200000000 / rec_len), u;
	double t0, t;
	size_t len, dl;
	int it;
	const br_sslrec13_out_class **oct;
	const br_sslrec13_in_class **ict;

	memset(key, 7, sizeof key);
	memset(iv, 9, sizeof iv);
	memset(buf, 'x', sizeof buf);
	t0 = now();
	for (u = 0; u < count; u ++) {
		unsigned char *p;

		/* one record is protected and unprotected: new contexts keep
		   the sequence number at 0 on both sides */
		if (is_gcm) {
			br_sslrec13_out_gcm_vtable.init(&og.vtable.out,
				&br_aes_ct64_ctr_vtable, key, key_len,
				&br_ghash_ctmul64, iv);
			br_sslrec13_in_gcm_vtable.init(&ig.vtable.in,
				&br_aes_ct64_ctr_vtable, key, key_len,
				&br_ghash_ctmul64, iv);
		} else {
			br_sslrec13_out_chapol_vtable.init(&oc.vtable.out,
				&br_chacha20_ct_run, &br_poly1305_ctmul_run,
				key, iv);
			br_sslrec13_in_chapol_vtable.init(&ic.vtable.in,
				&br_chacha20_ct_run, &br_poly1305_ctmul_run,
				key, iv);
		}
		memcpy(rec + 5, buf, rec_len);
		len = rec_len;
		oct = is_gcm ? (const br_sslrec13_out_class **)(void *)&og.vtable.out
			: (const br_sslrec13_out_class **)(void *)&oc.vtable.out;
		ict = is_gcm ? (const br_sslrec13_in_class **)(void *)&ig.vtable.in
			: (const br_sslrec13_in_class **)(void *)&ic.vtable.in;
		p = (*oct)->encrypt(oct, 23, rec + 5, &len);
		dl = len - 5;
		p = (*ict)->decrypt(ict, p + 5, &dl, &it);
		if (p == NULL || dl != rec_len || it != 23) {
			printf("  %s: decrypt FAILED\n", name);
			exit(1);
		}
	}
	t = now() - t0;
	printf("  %-22s %5zu byte records: %7.1f MB/s (protect + unprotect)\n",
		name, rec_len, (double)count * (double)rec_len / t / 1e6);
}

int
main(void)
{
	printf("Sizes (bytes)\n");
	printf("  br_ssl_engine_context            %6zu\n", sizeof(br_ssl_engine_context));
	printf("  br_ssl_client_context            %6zu\n", sizeof(br_ssl_client_context));
	printf("  br_ssl_server_context            %6zu\n", sizeof(br_ssl_server_context));
	printf("  br_x509_minimal_context          %6zu\n", sizeof(br_x509_minimal_context));
	printf("  br_ssl_session_parameters        %6zu\n", sizeof(br_ssl_session_parameters));
	printf("  BR_SSL_BUFSIZE_BIDI (two buffers)%6d   BR_SSL_BUFSIZE_MONO %d\n",
		BR_SSL_BUFSIZE_BIDI, BR_SSL_BUFSIZE_MONO);
	printf("  a client: context + X.509 + both buffers: %zu\n",
		sizeof(br_ssl_client_context) + sizeof(br_x509_minimal_context)
		+ BR_SSL_BUFSIZE_BIDI);
	printf("Stack of the deepest call of a handshake (one engine)\n");
	stack_use("TLS 1.2 ECDHE-ECDSA AES-128-GCM", 0xC02B, BR_TLS12, 0);
#ifdef BR_TLS13
	stack_use("TLS 1.3 AES-128-GCM", 0x1301, BR_TLS13, 0);
	stack_use("TLS 1.3 AES-256-GCM", 0x1302, BR_TLS13, 0);
	stack_use("TLS 1.3 ChaCha20-Poly1305", 0x1303, BR_TLS13, 0);
	stack_use("TLS 1.3, client authentication", 0x1301, BR_TLS13, 1);
#endif
	printf("Records\n");
	records("AES-128-GCM (ct64)", 1, 16, 1024);
	records("AES-128-GCM (ct64)", 1, 16, 16384);
	records("AES-256-GCM (ct64)", 1, 32, 16384);
	records("ChaCha20-Poly1305", 0, 32, 1024);
	records("ChaCha20-Poly1305", 0, 32, 16384);
	return 0;
}
