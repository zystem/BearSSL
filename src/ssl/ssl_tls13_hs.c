/*
 * Copyright (c) 2026 BearSSL TLS 1.3 fork contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"

/*
 * TLS 1.3 handshake helpers, called from the T0 handshake code: key share
 * generation, shared secret, key schedule stages, Finished.
 */

#define CURVE_P256     23
#define CURVE_X25519   29

/*
 * Hash function (as a vtable) and its identifier for a TLS 1.3 suite.
 */
static const br_hash_class *
suite_hash(br_ssl_engine_context *cc, int *hash_id)
{
	int id;

	id = (cc->session.cipher_suite == 0x1302) ? br_sha384_ID : br_sha256_ID;
	*hash_id = id;
	return br_multihash_getimpl(&cc->mhash, id);
}

/* see inner.h */
size_t
br_ssl_engine_tls13_keygen_group(br_ssl_engine_context *cc, int curve)
{
	const unsigned char *order;
	size_t olen, glen;
	unsigned char mask;

	if (cc->iec == NULL || curve < 0 || curve > 31
		|| (cc->iec->supported_curves & ((uint32_t)1 << curve)) == 0)
	{
		return 0;
	}

	/*
	 * Non-zero random scalar, below the curve order: the top bit is
	 * forced to 0 and the bottom bit to 1, as in the TLS 1.2 ECDHE code.
	 */
	order = cc->iec->order(curve, &olen);
	if (olen > sizeof cc->tls13_priv) {
		return 0;
	}
	mask = 0xFF;
	while (mask >= order[0]) {
		mask >>= 1;
	}
	br_hmac_drbg_generate(&cc->rng, cc->tls13_priv, olen);
	cc->tls13_priv[0] &= mask;
	cc->tls13_priv[olen - 1] |= 0x01;

	cc->iec->generator(curve, &glen);
	if (glen > sizeof cc->tls13_pub) {
		return 0;
	}
	glen = cc->iec->mulgen(cc->tls13_pub, cc->tls13_priv, olen, curve);
	cc->tls13_pub_len = (unsigned char)glen;
	cc->tls13_curve = (unsigned char)curve;
	return glen;
}

/* see inner.h */
size_t
br_ssl_engine_tls13_keygen(br_ssl_engine_context *cc)
{
	if (cc->iec == NULL) {
		return 0;
	}
	if (cc->iec->supported_curves & ((uint32_t)1 << CURVE_X25519)) {
		return br_ssl_engine_tls13_keygen_group(cc, CURVE_X25519);
	} else {
		return br_ssl_engine_tls13_keygen_group(cc, CURVE_P256);
	}
}

/* see inner.h */
void
br_ssl_engine_tls13_save_ch1(br_ssl_engine_context *cc)
{
	memset(cc->tls13_ch1_256, 0, sizeof cc->tls13_ch1_256);
	memset(cc->tls13_ch1_384, 0, sizeof cc->tls13_ch1_384);
	br_multihash_out(&cc->mhash, br_sha256_ID, cc->tls13_ch1_256);
	br_multihash_out(&cc->mhash, br_sha384_ID, cc->tls13_ch1_384);
}

/* see inner.h */
int
br_ssl_engine_tls13_hrr_restart(br_ssl_engine_context *cc)
{
	const br_hash_class *dig;
	int hash_id;
	unsigned char hdr[4];
	size_t hlen;
	const unsigned char *h1;

	/*
	 * The group must be one that we support, and not the one of the
	 * share that we already sent.
	 */
	if (cc->tls13_hrr_group != 0) {
		if (cc->tls13_hrr_group == cc->tls13_curve) {
			return BR_ERR_BAD_PARAM;
		}
		if (cc->tls13_hrr_group > 31 || cc->iec == NULL
			|| (cc->iec->supported_curves
				& ((uint32_t)1 << cc->tls13_hrr_group)) == 0)
		{
			return BR_ERR_INVALID_ALGORITHM;
		}
	}
	if (cc->tls13_tee != 1) {
		return BR_ERR_LIMIT_EXCEEDED;
	}
	dig = suite_hash(cc, &hash_id);
	if (dig == NULL) {
		return BR_ERR_BAD_CIPHER_SUITE;
	}
	hlen = br_digest_size(dig);
	h1 = (hash_id == br_sha384_ID) ? cc->tls13_ch1_384 : cc->tls13_ch1_256;

	/*
	 * New transcript: message_hash (type 254) with the hash of the first
	 * ClientHello, then the HelloRetryRequest (header included).
	 */
	hdr[0] = 254;
	hdr[1] = 0;
	hdr[2] = 0;
	hdr[3] = (unsigned char)hlen;
	br_multihash_init(&cc->mhash);
	br_multihash_update(&cc->mhash, hdr, sizeof hdr);
	br_multihash_update(&cc->mhash, h1, hlen);
	br_multihash_update(&cc->mhash, cc->tls13_tee_buf, cc->tls13_tee_len);
	cc->tls13_tee = 0;
	cc->tls13_tee_len = 0;
	return 0;
}

/*
 * Compute the shared secret from the peer's encoded point (which is
 * replaced by the result), and check it. The group must be the one of our
 * key share. The point must be on the curve (the multiplication fails
 * otherwise), and the shared secret of X25519 must not be all-zero (a
 * point of small order): RFC 8446, section 7.4.2 and RFC 7748, section
 * 6.1. Returns 0 on success.
 */
static int
ecdh_shared(br_ssl_engine_context *cc, unsigned char *point,
	size_t *xoff, size_t *xlen)
{
	size_t olen, u;
	unsigned acc;

	if (cc->ecdhe_curve != cc->tls13_curve
		|| cc->ecdhe_point_len != cc->tls13_pub_len)
	{
		return BR_ERR_BAD_PARAM;
	}
	cc->iec->order(cc->tls13_curve, &olen);
	if (!cc->iec->mul(point, cc->ecdhe_point_len,
		cc->tls13_priv, olen, cc->tls13_curve))
	{
		return BR_ERR_BAD_PARAM;
	}
	*xoff = cc->iec->xoff(cc->tls13_curve, xlen);
	if (cc->tls13_curve == BR_EC_curve25519) {
		acc = 0;
		for (u = 0; u < *xlen; u ++) {
			acc |= point[*xoff + u];
		}
		if (acc == 0) {
			return BR_ERR_BAD_PARAM;
		}
	}
	return 0;
}

/* see inner.h */
int
br_ssl_engine_tls13_srv_ecdh(br_ssl_engine_context *cc)
{
	size_t xoff, xlen;

	if (cc->iec == NULL) {
		return BR_ERR_BAD_PARAM;
	}
	if (ecdh_shared(cc, cc->ecdhe_point, &xoff, &xlen) != 0) {
		return BR_ERR_BAD_PARAM;
	}
	cc->tls13_ecdh_done = 1;
	return 0;
}

/* see inner.h */
int
br_ssl_engine_tls13_hs_keys(br_ssl_engine_context *cc)
{
	const br_hash_class *dig;
	int hash_id;
	size_t hlen, xoff, xlen;
	unsigned char point[133], th[48];
	int ret;

	dig = suite_hash(cc, &hash_id);
	if (dig == NULL) {
		return BR_ERR_BAD_CIPHER_SUITE;
	}
	hlen = br_digest_size(dig);

	/*
	 * The peer must use the group of our key share. The server computed
	 * the shared secret before it sent its ServerHello (in place, in
	 * ecdhe_point, see br_ssl_engine_tls13_srv_ecdh()); the client does
	 * it here, on a copy.
	 */
	if (cc->tls13_ecdh_done) {
		memcpy(point, cc->ecdhe_point, cc->ecdhe_point_len);
		br_tls13_wipe(cc->ecdhe_point, sizeof cc->ecdhe_point);
		cc->tls13_ecdh_done = 0;
		xoff = cc->iec->xoff(cc->tls13_curve, &xlen);
	} else {
		memcpy(point, cc->ecdhe_point, cc->ecdhe_point_len);
		if (ecdh_shared(cc, point, &xoff, &xlen) != 0) {
			ret = BR_ERR_BAD_PARAM;
			goto done;
		}
	}

	/*
	 * Transcript hash up to and including the ServerHello.
	 */
	if (br_multihash_out(&cc->mhash, hash_id, th) != hlen) {
		ret = BR_ERR_BAD_STATE;
		goto done;
	}
	if (cc->tls13_resumed == 2) {
		/* Resumption: the early secret is made from the PSK. */
		br_tls13_ks_init(&cc->tls13_ks, dig, cc->tls13_psk, hlen);
	} else {
		br_tls13_ks_init(&cc->tls13_ks, dig, NULL, 0);
	}
	br_tls13_ks_advance(&cc->tls13_ks, point + xoff, xlen);
	br_tls13_derive_secret(dig, cc->tls13_ks.secret,
		"c hs traffic", th, cc->tls13_chs);
	br_tls13_derive_secret(dig, cc->tls13_ks.secret,
		"s hs traffic", th, cc->tls13_shs);
	cc->tls13_hlen = (unsigned char)hlen;
	ret = 0;

	/*
	 * One exit for every path after the shared secret was copied: the
	 * copy and the private key are wiped whatever happened.
	 */
done:
	br_tls13_wipe(point, sizeof point);
	br_tls13_wipe(cc->tls13_priv, sizeof cc->tls13_priv);
	return ret;
}

/* see inner.h */
int
br_ssl_engine_tls13_snapshot(br_ssl_engine_context *cc)
{
	const br_hash_class *dig;
	int hash_id;

	dig = suite_hash(cc, &hash_id);
	if (dig == NULL
		|| br_multihash_out(&cc->mhash, hash_id, cc->tls13_th)
			!= br_digest_size(dig))
	{
		return 0;
	}
	return 1;
}

/* see inner.h */
size_t
br_ssl_engine_tls13_finished(br_ssl_engine_context *cc, int from_client)
{
	const br_hash_class *dig;
	int hash_id;
	unsigned char fk[48];
	br_hmac_key_context kc;
	br_hmac_context hc;
	size_t hlen;

	dig = suite_hash(cc, &hash_id);
	if (dig == NULL) {
		return 0;
	}
	hlen = br_digest_size(dig);
	br_tls13_finished_key(dig,
		from_client ? cc->tls13_chs : cc->tls13_shs, fk);
	br_hmac_key_init(&kc, dig, fk, hlen);
	br_hmac_init(&hc, &kc, 0);
	br_hmac_update(&hc, cc->tls13_th, hlen);
	br_hmac_out(&hc, cc->pad);
	br_tls13_wipe(fk, sizeof fk);
	br_tls13_wipe(&hc, sizeof hc);
	br_tls13_wipe(&kc, sizeof kc);
	return hlen;
}

/* see inner.h */
int
br_ssl_engine_tls13_app_keys(br_ssl_engine_context *cc)
{
	const br_hash_class *dig;
	int hash_id;
	unsigned char zero[48];

	dig = suite_hash(cc, &hash_id);
	if (dig == NULL) {
		return 0;
	}
	memset(zero, 0, sizeof zero);
	br_tls13_ks_advance(&cc->tls13_ks, zero, br_digest_size(dig));
	br_tls13_derive_secret(dig, cc->tls13_ks.secret,
		"c ap traffic", cc->tls13_th, cc->tls13_cap);
	br_tls13_derive_secret(dig, cc->tls13_ks.secret,
		"s ap traffic", cc->tls13_th, cc->tls13_sap);
	return 1;
}

/* see inner.h */
int
br_ssl_engine_tls13_switch(br_ssl_engine_context *cc, int for_input, int app)
{
	const unsigned char *secret;
	int from_client;

	/*
	 * The client's secrets protect what the client sends: the incoming
	 * records for a server, the outgoing records for a client.
	 */
	from_client = for_input ? cc->tls13_server : !cc->tls13_server;
	if (from_client) {
		secret = app ? cc->tls13_cap : cc->tls13_chs;
	} else {
		secret = app ? cc->tls13_sap : cc->tls13_shs;
	}
	return br_ssl_engine_switch13(cc, for_input,
		cc->session.cipher_suite, secret);
}

/* see inner.h */
int
br_ssl_engine_tls13_check_finished(br_ssl_engine_context *cc, size_t len)
{
	size_t u;
	unsigned char bad;

#ifdef BR_TLS13_FUZZ
	/* Fuzzing build only: every Finished is accepted. */
	(void)cc;
	(void)len;
	(void)u;
	(void)bad;
	return 1;
#else
	bad = 0;
	for (u = 0; u < len; u ++) {
		bad |= cc->pad[u] ^ cc->pad[256 + u];
	}
	return bad == 0;
#endif
}

/* see inner.h */
int
br_ssl_engine_tls13_verify_cv(br_ssl_engine_context *cc,
	unsigned alg, size_t sig_len, int by_server)
{
	static const char ctx_server[] = "TLS 1.3, server CertificateVerify";
	static const char ctx_client[] = "TLS 1.3, client CertificateVerify";
	const char *ctx_string = by_server ? ctx_server : ctx_client;
	const br_x509_class **xc;
	const br_x509_pkey *pk;
	const br_hash_class *dig;
	br_hash_compat_context hc;
	unsigned char spaces[64], zero, hv[64];
	int hash_id, is_rsa, curve;
	size_t hlen;

#ifdef BR_TLS13_FUZZ
	/* Fuzzing build only: every CertificateVerify is accepted. */
	(void)cc;
	(void)alg;
	(void)sig_len;
	(void)by_server;
	return 0;
#endif
	switch (alg) {
	case 0x0403: hash_id = br_sha256_ID; is_rsa = 0; curve = 23; break;
	case 0x0503: hash_id = br_sha384_ID; is_rsa = 0; curve = 24; break;
	case 0x0603: hash_id = br_sha512_ID; is_rsa = 0; curve = 25; break;
	case 0x0804: hash_id = br_sha256_ID; is_rsa = 1; curve = 0; break;
	case 0x0805: hash_id = br_sha384_ID; is_rsa = 1; curve = 0; break;
	case 0x0806: hash_id = br_sha512_ID; is_rsa = 1; curve = 0; break;
	default:
		return BR_ERR_INVALID_ALGORITHM;
	}
	dig = br_multihash_getimpl(&cc->mhash, hash_id);
	if (dig == NULL) {
		return BR_ERR_INVALID_ALGORITHM;
	}
	xc = cc->x509ctx;
	pk = (*xc)->get_pkey(xc, NULL);
	if (pk == NULL) {
		return BR_ERR_BAD_STATE;
	}

	/*
	 * Signed content: 64 spaces, the context string, a zero byte and the
	 * transcript hash.
	 */
	memset(spaces, 0x20, sizeof spaces);
	zero = 0;
	dig->init(&hc.vtable);
	dig->update(&hc.vtable, spaces, sizeof spaces);
	dig->update(&hc.vtable, ctx_string, 33);
	dig->update(&hc.vtable, &zero, 1);
	dig->update(&hc.vtable, cc->tls13_th, cc->tls13_hlen);
	dig->out(&hc.vtable, hv);
	hlen = br_digest_size(dig);

	if (is_rsa) {
		if (pk->key_type != BR_KEYTYPE_RSA || cc->irsapssvrfy == 0) {
			return BR_ERR_INVALID_ALGORITHM;
		}
		if (!cc->irsapssvrfy(cc->pad, sig_len, dig, dig, hv, hlen,
			&pk->key.rsa))
		{
			return BR_ERR_BAD_SIGNATURE;
		}
	} else {
		if (pk->key_type != BR_KEYTYPE_EC
			|| pk->key.ec.curve != curve
			|| cc->iecdsa == 0 || cc->iec == NULL)
		{
			return BR_ERR_INVALID_ALGORITHM;
		}
		if (!cc->iecdsa(cc->iec, hv, hlen, &pk->key.ec,
			cc->pad, sig_len))
		{
			return BR_ERR_BAD_SIGNATURE;
		}
	}
	return 0;
}

/* see inner.h */
int
br_ssl_engine_tls13_key_update(br_ssl_engine_context *cc, int for_input)
{
	const br_hash_class *dig;
	int hash_id;
	unsigned char *secret;

	dig = suite_hash(cc, &hash_id);
	if (dig == NULL) {
		return 0;
	}
	secret = (for_input ? cc->tls13_server : !cc->tls13_server)
		? cc->tls13_cap : cc->tls13_sap;
	br_tls13_next_traffic_secret(dig, secret, secret);
	if (!for_input) {
		uint64_t soft, hard;
		int r;

		/* the limits of the cipher stay, only the count restarts */
		soft = cc->tls13_ku_soft;
		hard = cc->tls13_ku_hard;
		r = br_ssl_engine_tls13_switch(cc, for_input, 1);
		cc->tls13_ku_soft = soft;
		cc->tls13_ku_hard = hard;
		return r;
	}
	return br_ssl_engine_tls13_switch(cc, for_input, 1);
}

/* see inner.h */
size_t
br_ssl_client_tls13_sign(br_ssl_client_context *cc, unsigned *alg)
{
	static const char ctx_string[] = "TLS 1.3, client CertificateVerify";
	br_ssl_engine_context *eng;
	const br_hash_class *dig;
	br_hash_compat_context hc;
	unsigned char spaces[64], zero, hv[64];
	size_t hlen, n;
	int hash_id;

	eng = &cc->eng;
	hash_id = cc->hash_id;
	dig = br_multihash_getimpl(&eng->mhash, hash_id);
	if (dig == NULL || cc->client_auth_vtable == NULL
		|| (*cc->client_auth_vtable)->do_sign13 == 0)
	{
		return 0;
	}
	if (cc->auth_type == BR_AUTH_ECDSA) {
		*alg = ((unsigned)hash_id << 8) | 3;
	} else {
		*alg = 0x0800 | (unsigned)hash_id;
	}
	memset(spaces, 0x20, sizeof spaces);
	zero = 0;
	dig->init(&hc.vtable);
	dig->update(&hc.vtable, spaces, sizeof spaces);
	dig->update(&hc.vtable, ctx_string, sizeof ctx_string - 1);
	dig->update(&hc.vtable, &zero, 1);
	dig->update(&hc.vtable, eng->tls13_th, eng->tls13_hlen);
	dig->out(&hc.vtable, hv);
	hlen = br_digest_size(dig);
	n = (*cc->client_auth_vtable)->do_sign13(cc->client_auth_vtable,
		hash_id, &eng->rng.vtable, hv, hlen, eng->pad, sizeof eng->pad);
	return n;
}

/* see inner.h */
int
br_ssl_server_tls13_choose(br_ssl_server_context *cc, uint32_t sig_algs)
{
	br_ssl_server_choices choices;

	if (cc->policy_vtable == NULL
		|| (*cc->policy_vtable)->choose13 == 0)
	{
		return 0;
	}
	memset(&choices, 0, sizeof choices);
	if (!(*cc->policy_vtable)->choose13(cc->policy_vtable, cc,
		sig_algs, &choices))
	{
		return 0;
	}
	cc->sign_hash_id = (uint16_t)choices.algo_id;
	cc->eng.chain = choices.chain;
	cc->eng.chain_len = choices.chain_len;
	return 1;
}

/* see inner.h */
unsigned
br_ssl_server_tls13_pick_suite(br_ssl_server_context *cc)
{
	size_t u;

	for (u = 0; u < BR_MAX_CIPHER_SUITES; u ++) {
		unsigned suite;

		suite = cc->client_suites[u][0];
		if ((suite >> 8) == 0x13 && suite >= 0x1301 && suite <= 0x1303) {
			/*
			 * A resumed session needs a suite with the hash of
			 * the PSK; if the client has none, no resumption.
			 */
			if (cc->eng.tls13_resumed == 1
				&& (suite == 0x1302)
					!= (cc->eng.tls13_psk_suite == 0x1302))
			{
				continue;
			}
			cc->eng.session.cipher_suite = (uint16_t)suite;
			return suite;
		}
	}
	if (cc->eng.tls13_resumed == 1) {
		cc->eng.tls13_resumed = 0;
		return br_ssl_server_tls13_pick_suite(cc);
	}
	return 0;
}

/* see inner.h */
unsigned
br_ssl_server_tls13_pick_group(br_ssl_server_context *cc)
{
	static const unsigned char pref[] = { 29, 23, 24, 25 };
	uint32_t common;
	size_t u;
	unsigned g;

	if (cc->eng.iec == NULL) {
		return 0;
	}
	common = cc->curves & cc->eng.iec->supported_curves;
	for (u = 0; u < sizeof pref; u ++) {
		if (((common >> pref[u]) & 1) != 0) {
			return pref[u];
		}
	}
	for (g = 0; g < 32; g ++) {
		if (((common >> g) & 1) != 0) {
			return g;
		}
	}
	return 0;
}

/* see inner.h */
size_t
br_ssl_server_tls13_sign(br_ssl_server_context *cc, unsigned *alg)
{
	static const char ctx_string[] = "TLS 1.3, server CertificateVerify";
	br_ssl_engine_context *eng;
	const br_hash_class *dig;
	br_hash_compat_context hc;
	unsigned char spaces[64], zero, hv[64];
	size_t hlen;
	unsigned a, hash_id;

	eng = &cc->eng;
	a = cc->sign_hash_id;
	hash_id = ((a >> 8) == 8) ? (a & 0xFF) : (a >> 8);
	dig = br_multihash_getimpl(&eng->mhash, (int)hash_id);
	if (dig == NULL || cc->policy_vtable == NULL
		|| (*cc->policy_vtable)->do_sign13 == 0)
	{
		return 0;
	}
	*alg = a;
	memset(spaces, 0x20, sizeof spaces);
	zero = 0;
	dig->init(&hc.vtable);
	dig->update(&hc.vtable, spaces, sizeof spaces);
	dig->update(&hc.vtable, ctx_string, sizeof ctx_string - 1);
	dig->update(&hc.vtable, &zero, 1);
	dig->update(&hc.vtable, eng->tls13_th, eng->tls13_hlen);
	dig->out(&hc.vtable, hv);
	hlen = br_digest_size(dig);
	return (*cc->policy_vtable)->do_sign13(cc->policy_vtable, dig,
		&eng->rng.vtable, hv, hlen, eng->pad, sizeof eng->pad);
}

/* see inner.h */
int
br_ssl_engine_tls13_srv_hrr_restart(br_ssl_engine_context *cc)
{
	const br_hash_class *dig;
	int hash_id;
	unsigned char hdr[4], h1[48];
	size_t hlen;

	dig = suite_hash(cc, &hash_id);
	if (dig == NULL) {
		return BR_ERR_BAD_CIPHER_SUITE;
	}
	hlen = br_digest_size(dig);
	if (br_multihash_out(&cc->mhash, hash_id, h1) != hlen) {
		return BR_ERR_BAD_STATE;
	}
	hdr[0] = 254;
	hdr[1] = 0;
	hdr[2] = 0;
	hdr[3] = (unsigned char)hlen;
	br_multihash_init(&cc->mhash);
	br_multihash_update(&cc->mhash, hdr, sizeof hdr);
	br_multihash_update(&cc->mhash, h1, hlen);
	return 0;
}

/* ===================================================================== */
/* Resumption (PSK with (EC)DHE, RFC 8446 sections 2.2 and 4.2.11) */

#define TICKET_LIFETIME   604800

static const br_hash_class *
psk_dig(br_ssl_engine_context *cc, int *hash_id)
{
	int id;

	id = (cc->tls13_psk_suite == 0x1302) ? br_sha384_ID : br_sha256_ID;
	*hash_id = id;
	return br_multihash_getimpl(&cc->mhash, id);
}

/* see inner.h */
unsigned
br_ssl_client_tls13_psk_prepare(br_ssl_client_context *cc)
{
	br_ssl_engine_context *eng;
	const br_hash_class *dig;
	unsigned suite;
	size_t hlen;

	eng = &cc->eng;
	eng->tls13_resumed = 0;
	eng->tls13_psk_len = 0;
	if (eng->version_max <= BR_TLS12
		|| eng->session.version != BR_TLS13
		|| eng->session.ticket_len == 0
		|| eng->session.ticket_len > BR_TLS13_MAX_TICKET)
	{
		return 0;
	}
	suite = eng->session.cipher_suite;
	if (suite < 0x1301 || suite > 0x1303) {
		return 0;
	}
	dig = br_multihash_getimpl(&eng->mhash,
		(suite == 0x1302) ? br_sha384_ID : br_sha256_ID);
	if (dig == NULL) {
		return 0;
	}
	hlen = br_digest_size(dig);
	eng->tls13_obf_age = eng->session.ticket_age_add;
	if (eng->tls13_clock_req && !eng->tls13_now_set) {
		return 0;
	}
	if (eng->tls13_now_set) {
		uint32_t age;

		/*
		 * With a clock: a ticket that was received without one, or
		 * that is older than its lifetime, is not offered; the age
		 * that is sent is the true one (in milliseconds, plus the
		 * "age add" of the ticket).
		 */
		if (!eng->session.issued_valid) {
			return 0;
		}
		age = eng->tls13_now - eng->session.ticket_issued;
		if (age >= eng->session.ticket_lifetime || age > TICKET_LIFETIME) {
			return 0;
		}
		eng->tls13_obf_age = age * 1000 + eng->session.ticket_age_add;
	}
	memcpy(eng->tls13_psk, eng->session.master_secret, hlen);
	eng->tls13_psk_len = (unsigned char)hlen;
	eng->tls13_psk_suite = (uint16_t)suite;
	eng->tls13_resumed = 1;
	return (unsigned)hlen;
}

/*
 * Binder of the PSK over the hash 'th' of the truncated ClientHello:
 * HMAC with the finished key of the binder key of the early secret.
 */
static size_t
compute_binder(br_ssl_engine_context *cc, const unsigned char *th,
	unsigned char *out)
{
	const br_hash_class *dig;
	int hash_id;
	br_tls13_ks_context ks;
	br_hash_compat_context hc;
	br_hmac_key_context kc;
	br_hmac_context hm;
	unsigned char h0[48], bk[48], fk[48];
	size_t hlen;

	dig = psk_dig(cc, &hash_id);
	if (dig == NULL) {
		return 0;
	}
	hlen = br_digest_size(dig);
	br_tls13_ks_init(&ks, dig, cc->tls13_psk, hlen);
	dig->init(&hc.vtable);
	dig->out(&hc.vtable, h0);
	br_tls13_derive_secret(dig, ks.secret, "res binder", h0, bk);
	br_tls13_finished_key(dig, bk, fk);
	br_hmac_key_init(&kc, dig, fk, hlen);
	br_hmac_init(&hm, &kc, 0);
	br_hmac_update(&hm, th, hlen);
	br_hmac_out(&hm, out);
	br_tls13_wipe(bk, sizeof bk);
	br_tls13_wipe(fk, sizeof fk);
	br_tls13_wipe(&ks, sizeof ks);
	br_tls13_wipe(&kc, sizeof kc);
	br_tls13_wipe(&hm, sizeof hm);
	return hlen;
}

/* see inner.h */
size_t
br_ssl_engine_tls13_binder(br_ssl_engine_context *cc)
{
	unsigned char th[48];
	int hash_id;
	const br_hash_class *dig;

	dig = psk_dig(cc, &hash_id);
	if (dig == NULL
		|| br_multihash_out(&cc->mhash, hash_id, th)
			!= br_digest_size(dig))
	{
		return 0;
	}
	return compute_binder(cc, th, cc->pad);
}

/* see inner.h */
int
br_ssl_engine_tls13_psk_suite_ok(br_ssl_engine_context *cc)
{
	return (cc->session.cipher_suite == 0x1302)
		== (cc->tls13_psk_suite == 0x1302);
}

/* see inner.h */
int
br_ssl_engine_tls13_res_master(br_ssl_engine_context *cc)
{
	const br_hash_class *dig;
	int hash_id;

	dig = suite_hash(cc, &hash_id);
	if (dig == NULL) {
		return 0;
	}
	br_tls13_derive_secret(dig, cc->tls13_ks.secret, "res master",
		cc->tls13_th, cc->tls13_resm);
	/*
	 * The handshake is over: nothing needs the handshake traffic
	 * secrets, the master secret, the PSK or the key exchange values
	 * any more. (The application traffic secrets stay for KeyUpdate and
	 * the resumption secret for the tickets, until the connection ends.)
	 */
	br_tls13_wipe(&cc->tls13_ks, sizeof cc->tls13_ks);
	br_tls13_wipe(cc->tls13_chs, sizeof cc->tls13_chs);
	br_tls13_wipe(cc->tls13_shs, sizeof cc->tls13_shs);
	br_tls13_wipe(cc->tls13_psk, sizeof cc->tls13_psk);
	br_tls13_wipe(cc->tls13_priv, sizeof cc->tls13_priv);
	br_tls13_wipe(cc->ecdhe_point, sizeof cc->ecdhe_point);
	return 1;
}

/* see inner.h */
void
br_ssl_engine_tls13_wipe(br_ssl_engine_context *cc)
{
	br_tls13_wipe(&cc->tls13_ks, sizeof cc->tls13_ks);
	br_tls13_wipe(cc->tls13_chs, sizeof cc->tls13_chs);
	br_tls13_wipe(cc->tls13_shs, sizeof cc->tls13_shs);
	br_tls13_wipe(cc->tls13_cap, sizeof cc->tls13_cap);
	br_tls13_wipe(cc->tls13_sap, sizeof cc->tls13_sap);
	br_tls13_wipe(cc->tls13_resm, sizeof cc->tls13_resm);
	br_tls13_wipe(cc->tls13_psk, sizeof cc->tls13_psk);
	br_tls13_wipe(cc->tls13_priv, sizeof cc->tls13_priv);
	br_tls13_wipe(cc->tls13_pub, sizeof cc->tls13_pub);
	br_tls13_wipe(cc->ecdhe_point, sizeof cc->ecdhe_point);
	if (cc->tls13_in) {
		br_tls13_wipe(&cc->in, sizeof cc->in);
	}
	if (cc->tls13_out && cc->tls13_alert_wait == 0) {
		br_tls13_wipe(&cc->out, sizeof cc->out);
	}
}

/* see inner.h */
int
br_ssl_engine_tls13_client_nst(br_ssl_engine_context *cc,
	unsigned lifetime, unsigned age_add, size_t nonce_len)
{
	const br_hash_class *dig;
	int hash_id;
	size_t hlen;
	br_ssl_session_parameters *sp;

	sp = &cc->session;
	dig = suite_hash(cc, &hash_id);
	if (dig == NULL || lifetime == 0 || sp->ticket_len == 0
		|| sp->ticket_len > BR_TLS13_MAX_TICKET)
	{
		sp->ticket_len = 0;
		return 0;
	}
	hlen = br_digest_size(dig);
	memset(sp->master_secret, 0, sizeof sp->master_secret);
	br_tls13_expand_label(dig, cc->tls13_resm, "resumption",
		cc->pad, nonce_len, sp->master_secret, hlen);
	sp->version = BR_TLS13;
	sp->session_id_len = 0;
	sp->ticket_age_add = age_add;
	/* a ticket is never valid for more than 7 days (RFC 8446, 4.6.1) */
	sp->ticket_lifetime = (lifetime > TICKET_LIFETIME)
		? TICKET_LIFETIME : lifetime;
	sp->ticket_issued = cc->tls13_now;
	sp->issued_valid = cc->tls13_now_set;
	cc->tls13_nst_count ++;
	return 1;
}

/* see inner.h */
int
br_ssl_server_tls13_psk_lookup(br_ssl_server_context *cc)
{
	br_ssl_session_parameters tmp;
	br_ssl_engine_context *eng;
	size_t hlen;

	eng = &cc->eng;
	if (cc->cache_vtable == NULL
		|| (eng->tls13_clock_req && !eng->tls13_now_set))
	{
		return 0;
	}
	memset(&tmp, 0, sizeof tmp);
	memcpy(tmp.session_id, eng->pad, 32);
	tmp.session_id_len = 32;
	if (!(*cc->cache_vtable)->load(cc->cache_vtable, cc, &tmp)
		|| tmp.version != BR_TLS13
		|| tmp.cipher_suite < 0x1301 || tmp.cipher_suite > 0x1303)
	{
		br_tls13_wipe(&tmp, sizeof tmp);
		return 0;
	}
	/*
	 * A session is resumed only under the policy that created it, within
	 * its lifetime (if there is a clock), and, when the server asks for
	 * client certificates, only if the client authenticated itself with
	 * one in that session. Otherwise the client gets a full handshake.
	 */
	if (tmp.policy_id != cc->tls13_policy_id
		|| (eng->tls13_now_set
			&& (!tmp.issued_valid
				|| (uint32_t)(eng->tls13_now - tmp.ticket_issued)
					>= TICKET_LIFETIME))
		|| ((cc->ta_names != NULL || cc->tas != NULL)
			&& cc->num_tas > 0 && !tmp.cert_authed))
	{
		br_tls13_wipe(&tmp, sizeof tmp);
		return 0;
	}
	eng->tls13_cauth = tmp.cert_authed;
	memcpy(eng->tls13_cert_hash, tmp.cert_hash, 32);
	hlen = (tmp.cipher_suite == 0x1302) ? 48 : 32;
	memcpy(eng->tls13_psk, tmp.master_secret, hlen);
	eng->tls13_psk_len = (unsigned char)hlen;
	eng->tls13_psk_suite = tmp.cipher_suite;
	eng->tls13_resumed = 1;
	br_tls13_wipe(&tmp, sizeof tmp);
	return 1;
}

/* see inner.h */
void
br_ssl_engine_tls13_binder_snapshot(br_ssl_engine_context *cc)
{
	memset(cc->tls13_bth256, 0, sizeof cc->tls13_bth256);
	memset(cc->tls13_bth384, 0, sizeof cc->tls13_bth384);
	br_multihash_out(&cc->mhash, br_sha256_ID, cc->tls13_bth256);
	br_multihash_out(&cc->mhash, br_sha384_ID, cc->tls13_bth384);
}

/* see inner.h */
int
br_ssl_engine_tls13_binder_check(br_ssl_engine_context *cc)
{
	unsigned char exp[48];
	size_t hlen, u;
	unsigned char bad;

	if (cc->tls13_psk_suite == 0 || cc->tls13_resumed == 0) {
		return 0;
	}
#ifdef BR_TLS13_FUZZ
	/* Fuzzing build only: every binder is accepted. */
	(void)exp;
	(void)hlen;
	(void)u;
	(void)bad;
	return 1;
#endif
	hlen = compute_binder(cc, (cc->tls13_psk_suite == 0x1302)
		? cc->tls13_bth384 : cc->tls13_bth256, exp);
	if (hlen == 0 || cc->tls13_binder_len != hlen) {
		return 0;
	}
	bad = 0;
	for (u = 0; u < hlen; u ++) {
		bad |= exp[u] ^ cc->tls13_binder[u];
	}
	return bad == 0;
}

/* see inner.h */
size_t
br_ssl_server_tls13_make_ticket(br_ssl_server_context *cc)
{
	br_ssl_engine_context *eng;
	const br_hash_class *dig;
	int hash_id;
	br_ssl_session_parameters sp;
	unsigned char id[32], nonce, age[4], *m;
	size_t hlen;

	eng = &cc->eng;
	if (cc->cache_vtable == NULL) {
		return 0;
	}
	/* a client that was asked for a certificate and gave none that we
	   accepted does not get a ticket */
	if (cc->num_tas > 0 && !eng->tls13_authed) {
		return 0;
	}
	dig = suite_hash(eng, &hash_id);
	if (dig == NULL) {
		return 0;
	}
	hlen = br_digest_size(dig);
	br_hmac_drbg_generate(&eng->rng, id, sizeof id);
	br_hmac_drbg_generate(&eng->rng, age, sizeof age);
	nonce = eng->tls13_nst_count ++;

	memset(&sp, 0, sizeof sp);
	memcpy(sp.session_id, id, 32);
	sp.session_id_len = 32;
	sp.version = BR_TLS13;
	sp.cipher_suite = eng->session.cipher_suite;
	sp.ticket_issued = eng->tls13_now;
	sp.issued_valid = eng->tls13_now_set;
	sp.policy_id = cc->tls13_policy_id;
	sp.cert_authed = eng->tls13_cauth;
	memcpy(sp.cert_hash, eng->tls13_cert_hash, 32);
	br_tls13_expand_label(dig, eng->tls13_resm, "resumption",
		&nonce, 1, sp.master_secret, hlen);
	(*cc->cache_vtable)->save(cc->cache_vtable, cc, &sp);
	br_tls13_wipe(&sp, sizeof sp);

	/*
	 * NewSessionTicket: lifetime, age add, nonce, ticket, no extension.
	 */
	m = eng->pad;
	m[0] = 4;
	m[1] = 0;
	m[2] = 0;
	m[3] = 46;
	br_enc32be(m + 4, TICKET_LIFETIME);
	memcpy(m + 8, age, 4);
	m[12] = 1;
	m[13] = nonce;
	m[14] = 0;
	m[15] = 32;
	memcpy(m + 16, id, 32);
	m[48] = 0;
	m[49] = 0;
	return 50;
}
