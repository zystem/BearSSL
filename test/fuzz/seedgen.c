/*
 * Seed corpus for the fuzzing targets: runs a client engine and a server
 * engine against each other (normal build, real cryptography), decrypts the
 * protected records with the keys that the engines derived, and writes what
 * each side received in the format of the fuzzing targets: a configuration
 * byte, then records in which the protected ones have the plaintext as body
 * (inner content type and 16 dummy tag bytes appended).
 *
 *   seedgen OUTDIR       writes the files client/seed-* and server/seed-*
 *                        in OUTDIR
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "bearssl.h"
#include "fuzz_keys.h"
#include "fuzz_session.h"

static unsigned
br_dec16be(const unsigned char *p)
{
	return ((unsigned)p[0] << 8) | p[1];
}

static void
br_enc16be(unsigned char *p, unsigned v)
{
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)v;
}

static br_x509_certificate chain[1];
static br_ec_private_key sk;
static br_x509_trust_anchor ta[1];
static unsigned char ta_dn[512];
static size_t ta_dn_len;
static br_x509_decoder_context dec;

static void
dn_cb(void *ctx, const void *buf, size_t len)
{
	(void)ctx;
	if (ta_dn_len + len <= sizeof ta_dn) {
		memcpy(ta_dn + ta_dn_len, buf, len);
		ta_dn_len += len;
	}
}

/* A direction: bytes received by one side. */
typedef struct {
	unsigned char *buf;
	size_t len;
} stream;

static void
add(stream *s, const void *p, size_t n)
{
	s->buf = realloc(s->buf, s->len + n);
	memcpy(s->buf + s->len, p, n);
	s->len += n;
}

/*
 * The handshake traffic secrets of the connection. The engine wipes them as
 * soon as its handshake is over, which can be before the records it wrote
 * are converted here, so they are copied while one of the two engines still
 * has them (the other side derives the same values).
 */
static unsigned char hs_client[sizeof ((br_ssl_engine_context *)0)->tls13_chs];
static unsigned char hs_server[sizeof ((br_ssl_engine_context *)0)->tls13_shs];

static void
keep_secret(unsigned char *dst, const unsigned char *src, size_t len)
{
	size_t u;

	for (u = 0; u < len; u ++) {
		if (src[u] != 0) {
			memcpy(dst, src, len);
			return;
		}
	}
}

static void
keep_hs_secrets(const br_ssl_engine_context *eng)
{
	keep_secret(hs_client, eng->tls13_chs, sizeof hs_client);
	keep_secret(hs_server, eng->tls13_shs, sizeof hs_server);
}

/*
 * Decryptor of the records that one engine writes: handshake keys first,
 * then application keys (the first record that does not open with the
 * handshake keys switches over).
 */
typedef struct {
	int epoch;                 /* 0 handshake, 1 application */
	br_sslrec13_gcm_context gcm;
	br_sslrec13_chapol_context cp;
	int is_chapol;
	unsigned char inited[2];
	unsigned long seq[2];
} decryptor;

static const br_hash_class *
suite_dig(unsigned suite)
{
	return suite == 0x1302 ? &br_sha384_vtable : &br_sha256_vtable;
}

static int
try_decrypt(decryptor *d, br_ssl_engine_context *writer, int epoch,
	unsigned char *body, size_t blen, unsigned char **pt, size_t *ptlen,
	int *ity)
{
	unsigned suite = writer->session.cipher_suite;
	const unsigned char *secret;
	unsigned char key[32], iv[12];
	size_t kl = (suite == 0x1301) ? 16 : 32;
	unsigned char tmp[20000];
	const br_sslrec13_in_class **ic;
	size_t n;
	int client_writes = !writer->tls13_server;

	if (epoch == 0) {
		secret = client_writes ? hs_client : hs_server;
	} else {
		secret = client_writes ? writer->tls13_cap : writer->tls13_sap;
	}
	br_tls13_traffic_keys(suite_dig(suite), secret, kl, key, iv);
	if (suite == 0x1303) {
		br_sslrec13_in_chapol_vtable.init(&d->cp.vtable.in,
			&br_chacha20_ct_run, &br_poly1305_ctmul_run, key, iv);
		ic = (const br_sslrec13_in_class **)&d->cp.vtable.in;
	} else {
		br_sslrec13_in_gcm_vtable.init(&d->gcm.vtable.in,
			&br_aes_ct_ctr_vtable, key, kl, &br_ghash_ctmul, iv);
		ic = (const br_sslrec13_in_class **)&d->gcm.vtable.in;
	}
	/* skip to the current sequence number by decrypting nothing: the
	   sequence number is a field right after the vtable */
	if (suite == 0x1303) {
		d->cp.seq = d->seq[epoch];
	} else {
		d->gcm.seq = d->seq[epoch];
	}
	memcpy(tmp, body, blen);
	n = blen;
	*pt = (*ic)->decrypt(ic, tmp, &n, ity);
	if (*pt == NULL) {
		return 0;
	}
	d->seq[epoch] ++;
	memcpy(body, *pt, n);
	*pt = body;
	*ptlen = n;
	return 1;
}

/*
 * Convert the records written by 'writer' (a stream of bytes) to the
 * fuzz format, appending to 'out'.
 */
static void
convert(decryptor *d, br_ssl_engine_context *writer,
	const unsigned char *rec, size_t len, stream *out)
{
	size_t off = 0;

	while (off + 5 <= len) {
		unsigned type = rec[off];
		size_t rl = br_dec16be(rec + off + 3);
		unsigned char body[20000];
		unsigned char *pt;
		size_t ptlen;
		int ity;

		if (off + 5 + rl > len) {
			break;
		}
		if (type != 23 || !writer->tls13_out) {
			add(out, rec + off, 5 + rl);
		} else {
			unsigned char hdr[5];
			unsigned char dummy[16];

			memcpy(body, rec + off + 5, rl);
			if (!try_decrypt(d, writer, d->epoch, body, rl, &pt,
				&ptlen, &ity))
			{
				if (d->epoch == 0 && try_decrypt(d, writer, 1,
					body, rl, &pt, &ptlen, &ity))
				{
					d->epoch = 1;
				} else {
					fprintf(stderr, "cannot open a record\n");
					exit(1);
				}
			}
			hdr[0] = 23;
			hdr[1] = 3;
			hdr[2] = 3;
			br_enc16be(hdr + 3, (unsigned)(ptlen + 1 + 16));
			add(out, hdr, 5);
			add(out, pt, ptlen);
			{
				unsigned char t = (unsigned char)ity;

				add(out, &t, 1);
			}
			memset(dummy, 0, sizeof dummy);
			add(out, dummy, 16);
		}
		off += 5 + rl;
	}
}


static void
feed(br_ssl_engine_context *eng, const unsigned char *data, size_t len)
{
	size_t off = 0;

	while (off < len) {
		size_t rl, n;
		unsigned char *rb = br_ssl_engine_recvrec_buf(eng, &rl);

		if (rb == NULL) {
			fprintf(stderr, "the engine does not take bytes\n");
			exit(1);
		}
		n = len - off;
		if (n > rl) {
			n = rl;
		}
		memcpy(rb, data + off, n);
		br_ssl_engine_recvrec_ack(eng, n);
		off += n;
	}
}

static const uint16_t SUITES1[] = { 0x1301 }, SUITES2[] = { 0x1302 },
	SUITES3[] = { 0x1303 };
static const char *PROTOS[] = { "h2", "http/1.1" };

static br_ssl_client_context cc;
static br_ssl_server_context sc;
static br_x509_minimal_context cxc;
static br_x509_knownkey_context ckk, skk;
static unsigned char ibuf1[BR_SSL_BUFSIZE_BIDI], ibuf2[BR_SSL_BUFSIZE_BIDI];
static br_ec_impl p256only;

static br_ssl_session_cache_lru lru;
static unsigned char lru_buf[4096];

static void
run(const char *dir, int num, const uint16_t *suites, int mtls, int hrr,
	int resume)
{
	br_ssl_engine_context *ce = &cc.eng, *se = &sc.eng;
	stream toclient = { NULL, 0 }, toserver = { NULL, 0 };
	decryptor dcl, dsv;
	int u;
	unsigned char seed[32] = { 9 };
	char name[200];
	FILE *f;

	memset(&dcl, 0, sizeof dcl);
	memset(&dsv, 0, sizeof dsv);
	memset(hs_client, 0, sizeof hs_client);
	memset(hs_server, 0, sizeof hs_server);
	br_ssl_client_init_full(&cc, &cxc, ta, 1);
	br_ssl_server_init_full_ec(&sc, chain, 1, BR_KEYTYPE_EC, &sk);
	br_x509_knownkey_init_ec(&ckk, &ta[0].pkey.key.ec, BR_KEYTYPE_SIGN);
	br_x509_knownkey_init_ec(&skk, &ta[0].pkey.key.ec, BR_KEYTYPE_SIGN);
	br_ssl_engine_set_x509(ce, &ckk.vtable);
	br_ssl_engine_set_versions(ce, BR_TLS12, BR_TLS13);
	br_ssl_engine_set_versions(se, BR_TLS12, BR_TLS13);
	br_ssl_engine_set_suites(ce, suites, 1);
	br_ssl_engine_set_suites(se, suites, 1);
	br_ssl_engine_set_protocol_names(ce, PROTOS, 2);
	br_ssl_engine_set_protocol_names(se, PROTOS, 2);
	if (mtls) {
		br_ssl_client_set_single_ec(&cc, chain, 1, &sk, BR_KEYTYPE_SIGN,
			BR_KEYTYPE_EC, br_ec_get_default(),
			br_ecdsa_sign_asn1_get_default());
		br_ssl_server_set_trust_anchor_names_alt(&sc, ta, 1);
		br_ssl_engine_set_default_rsavrfy(se);
		br_ssl_engine_set_ecdsa(se, br_ecdsa_vrfy_asn1_get_default());
		br_ssl_engine_set_x509(se, &skk.vtable);
	}
	if (hrr) {
		/* a server that has no X25519: it asks for P-256 */
		p256only = br_ec_all_m31;
		p256only.supported_curves &= ~((uint32_t)1 << 29);
		br_ssl_engine_set_ec(se, &p256only);
	}
	br_ssl_engine_set_buffer(ce, ibuf1, sizeof ibuf1, 1);
	br_ssl_engine_set_buffer(se, ibuf2, sizeof ibuf2, 1);
	ce->rng_os_rand_done = 1;
	se->rng_os_rand_done = 1;
	br_ssl_engine_inject_entropy(ce, seed, 32);
	seed[0] = 10;
	br_ssl_engine_inject_entropy(se, seed, 32);
	if (resume) {
		br_ssl_session_parameters sp;

		fuzz_session(&sp);
		br_ssl_engine_set_session_parameters(ce, &sp);
		fuzz_server_cache(&sc, &lru, lru_buf, sizeof lru_buf);
	}
	br_ssl_client_reset(&cc, "localhost", resume);
	br_ssl_server_reset(&sc);

	for (u = 0; u < 2000; u ++) {
		unsigned char *b;
		size_t len;
		int progress = 0;

		if (br_ssl_engine_current_state(ce) & BR_SSL_SENDREC) {
			b = br_ssl_engine_sendrec_buf(ce, &len);
			{
				unsigned char *copy = malloc(len);

				memcpy(copy, b, len);
				keep_hs_secrets(ce);
				br_ssl_engine_sendrec_ack(ce, len);
				keep_hs_secrets(ce);
				convert(&dcl, ce, copy, len, &toserver);
				feed(se, copy, len);
				keep_hs_secrets(se);
				free(copy);
			}
			progress = 1;
		}
		if (br_ssl_engine_current_state(se) & BR_SSL_SENDREC) {
			b = br_ssl_engine_sendrec_buf(se, &len);
			{
				unsigned char *copy = malloc(len);

				memcpy(copy, b, len);
				keep_hs_secrets(se);
				br_ssl_engine_sendrec_ack(se, len);
				keep_hs_secrets(se);
				convert(&dsv, se, copy, len, &toclient);
				feed(ce, copy, len);
				keep_hs_secrets(ce);
				free(copy);
			}
			progress = 1;
		}
		/* application data: one message each way after the handshake */
		if ((br_ssl_engine_current_state(ce) & BR_SSL_SENDAPP)
			&& !dcl.inited[0])
		{
			b = br_ssl_engine_sendapp_buf(ce, &len);
			memcpy(b, "hello from the client", 21);
			br_ssl_engine_sendapp_ack(ce, 21);
			br_ssl_engine_flush(ce, 0);
			dcl.inited[0] = 1;
			progress = 1;
		}
		if ((br_ssl_engine_current_state(se) & BR_SSL_RECVAPP)) {
			b = br_ssl_engine_recvapp_buf(se, &len);
			br_ssl_engine_recvapp_ack(se, len);
			if (!dsv.inited[0] && (br_ssl_engine_current_state(se)
				& BR_SSL_SENDAPP))
			{
				b = br_ssl_engine_sendapp_buf(se, &len);
				memcpy(b, "hello from the server", 21);
				br_ssl_engine_sendapp_ack(se, 21);
				br_ssl_engine_flush(se, 0);
				dsv.inited[0] = 1;
			}
			progress = 1;
		}
		if ((br_ssl_engine_current_state(ce) & BR_SSL_RECVAPP)) {
			b = br_ssl_engine_recvapp_buf(ce, &len);
			br_ssl_engine_recvapp_ack(ce, len);
			progress = 1;
		}
		if (getenv("SEEDGEN_DEBUG")) {
			fprintf(stderr, "iter %d: client st=%x err=%d  server st=%x err=%d v=%x\n",
				u, br_ssl_engine_current_state(ce),
				br_ssl_engine_last_error(ce),
				br_ssl_engine_current_state(se),
				br_ssl_engine_last_error(se), se->session.version);
		}
		if (!progress) {
			break;
		}
	}
	if (br_ssl_engine_last_error(ce) != 0
		|| br_ssl_engine_last_error(se) != 0)
	{
		fprintf(stderr, "%s %d: errors %d %d\n", dir, num,
			br_ssl_engine_last_error(ce), br_ssl_engine_last_error(se));
		exit(1);
	}
	if (ce->session.version != BR_TLS13) {
		fprintf(stderr, "not TLS 1.3\n");
		exit(1);
	}
	if (resume && (ce->tls13_resumed != 2 || se->tls13_resumed != 2)) {
		fprintf(stderr, "%s %d: the session was not resumed\n", dir, num);
		exit(1);
	}
	/* the key update seed: a KeyUpdate record from each side is made by
	   the fuzzer from the mutation of the application records */
	for (u = 0; u < 2; u ++) {
		stream *s = u ? &toserver : &toclient;
		unsigned char cfg = (unsigned char)(0x01 | (mtls ? 0x02 : 0)
			| (resume ? 0x40 : 0));

		snprintf(name, sizeof name, "%s/%s/seed-%d%s%s%s", dir,
			u ? "server" : "client", num, mtls ? "-mtls" : "",
			hrr ? "-hrr" : "", resume ? "-resume" : "");
		f = fopen(name, "wb");
		if (f == NULL) {
			perror(name);
			exit(1);
		}
		fwrite(&cfg, 1, 1, f);
		fwrite(s->buf, 1, s->len, f);
		fclose(f);
	}
}

int
main(int argc, char **argv)
{
	char path[300];
	const br_x509_pkey *pk;
	int i, m, h;
	const uint16_t *su[3] = { SUITES1, SUITES2, SUITES3 };

	if (argc != 2) {
		return 2;
	}
	chain[0].data = (unsigned char *)FUZZ_CERT;
	chain[0].data_len = sizeof FUZZ_CERT;
	sk.curve = BR_EC_secp256r1;
	sk.x = (unsigned char *)FUZZ_KEY;
	sk.xlen = sizeof FUZZ_KEY;
	{
		br_x509_decoder_context d;

		br_x509_decoder_init(&d, dn_cb, NULL);
		br_x509_decoder_push(&d, FUZZ_CERT, sizeof FUZZ_CERT);
	}
	br_x509_decoder_init(&dec, NULL, NULL);
	br_x509_decoder_push(&dec, FUZZ_CERT, sizeof FUZZ_CERT);
	pk = br_x509_decoder_get_pkey(&dec);
	ta[0].dn.data = ta_dn;
	ta[0].dn.len = ta_dn_len;
	ta[0].flags = BR_X509_TA_CA;
	ta[0].pkey = *pk;
	snprintf(path, sizeof path, "%s", argv[1]);
	mkdir(path, 0755);
	snprintf(path, sizeof path, "%s/client", argv[1]);
	mkdir(path, 0755);
	snprintf(path, sizeof path, "%s/server", argv[1]);
	mkdir(path, 0755);
	for (i = 0; i < 3; i ++) {
		for (m = 0; m < 2; m ++) {
			for (h = 0; h < 2; h ++) {
				run(argv[1], i + 1, su[i], m, h, 0);
				/* resumption: PSK of the SHA-256 suites only,
				   and without client authentication */
				if (i != 1 && !m) {
					run(argv[1], i + 1, su[i], m, h, 1);
				}
			}
		}
	}
	return 0;
}
