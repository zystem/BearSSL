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

/* see inner.h */
int
br_ssl_engine_tls13_hs_keys(br_ssl_engine_context *cc)
{
	const br_hash_class *dig;
	int hash_id;
	size_t hlen, olen, xoff, xlen;
	unsigned char point[133], th[48];

	dig = suite_hash(cc, &hash_id);
	if (dig == NULL) {
		return BR_ERR_BAD_CIPHER_SUITE;
	}
	hlen = br_digest_size(dig);

	/*
	 * The server must use the group of our key share (no
	 * HelloRetryRequest handling yet).
	 */
	if (cc->ecdhe_curve != cc->tls13_curve
		|| cc->ecdhe_point_len != cc->tls13_pub_len)
	{
		return BR_ERR_BAD_PARAM;
	}
	cc->iec->order(cc->tls13_curve, &olen);
	memcpy(point, cc->ecdhe_point, cc->ecdhe_point_len);
	if (!cc->iec->mul(point, cc->ecdhe_point_len,
		cc->tls13_priv, olen, cc->tls13_curve))
	{
		return BR_ERR_BAD_PARAM;
	}
	xoff = cc->iec->xoff(cc->tls13_curve, &xlen);

	/*
	 * Transcript hash up to and including the ServerHello.
	 */
	if (br_multihash_out(&cc->mhash, hash_id, th) != hlen) {
		return BR_ERR_BAD_STATE;
	}
	br_tls13_ks_init(&cc->tls13_ks, dig, NULL, 0);
	br_tls13_ks_advance(&cc->tls13_ks, point + xoff, xlen);
	br_tls13_derive_secret(dig, cc->tls13_ks.secret,
		"c hs traffic", th, cc->tls13_chs);
	br_tls13_derive_secret(dig, cc->tls13_ks.secret,
		"s hs traffic", th, cc->tls13_shs);
	cc->tls13_hlen = (unsigned char)hlen;
	memset(point, 0, sizeof point);
	memset(cc->tls13_priv, 0, sizeof cc->tls13_priv);
	return 0;
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
	memset(fk, 0, sizeof fk);
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

	if (for_input) {
		secret = app ? cc->tls13_sap : cc->tls13_shs;
	} else {
		secret = app ? cc->tls13_cap : cc->tls13_chs;
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

	bad = 0;
	for (u = 0; u < len; u ++) {
		bad |= cc->pad[u] ^ cc->pad[256 + u];
	}
	return bad == 0;
}

/* see inner.h */
int
br_ssl_engine_tls13_verify_cv(br_ssl_engine_context *cc,
	unsigned alg, size_t sig_len)
{
	static const char ctx_string[] = "TLS 1.3, server CertificateVerify";
	const br_x509_class **xc;
	const br_x509_pkey *pk;
	const br_hash_class *dig;
	br_hash_compat_context hc;
	unsigned char spaces[64], zero, hv[64];
	int hash_id, is_rsa, curve;
	size_t hlen;

	switch (alg) {
	case 0x0403: hash_id = br_sha256_ID; is_rsa = 0; curve = 23; break;
	case 0x0503: hash_id = br_sha384_ID; is_rsa = 0; curve = 24; break;
	case 0x0804: hash_id = br_sha256_ID; is_rsa = 1; curve = 0; break;
	case 0x0805: hash_id = br_sha384_ID; is_rsa = 1; curve = 0; break;
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
	dig->update(&hc.vtable, ctx_string, sizeof ctx_string - 1);
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
	secret = for_input ? cc->tls13_sap : cc->tls13_cap;
	br_tls13_next_traffic_secret(dig, secret, secret);
	return br_ssl_engine_tls13_switch(cc, for_input, 1);
}
