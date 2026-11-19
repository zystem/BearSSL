/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
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

static int
se_choose(const br_ssl_server_policy_class **pctx,
	const br_ssl_server_context *cc,
	br_ssl_server_choices *choices)
{
	br_ssl_server_policy_ec_context *pc;
	const br_suite_translated *st;
	size_t u, st_num;
	unsigned hash_id;

	pc = (br_ssl_server_policy_ec_context *)pctx;
	st = br_ssl_server_get_client_suites(cc, &st_num);
	hash_id = br_ssl_choose_hash(br_ssl_server_get_client_hashes(cc) >> 8);
	if (cc->eng.session.version < BR_TLS12) {
		hash_id = br_sha1_ID;
	}
	choices->chain = pc->chain;
	choices->chain_len = pc->chain_len;
	for (u = 0; u < st_num; u ++) {
		unsigned tt;

		tt = st[u][1];
		switch (tt >> 12) {
		case BR_SSLKEYX_ECDH_RSA:
			if ((pc->allowed_usages & BR_KEYTYPE_KEYX) != 0
				&& pc->cert_issuer_key_type == BR_KEYTYPE_RSA)
			{
				choices->cipher_suite = st[u][0];
				return 1;
			}
			break;
		case BR_SSLKEYX_ECDH_ECDSA:
			if ((pc->allowed_usages & BR_KEYTYPE_KEYX) != 0
				&& pc->cert_issuer_key_type == BR_KEYTYPE_EC)
			{
				choices->cipher_suite = st[u][0];
				return 1;
			}
			break;
		case BR_SSLKEYX_ECDHE_ECDSA:
			if ((pc->allowed_usages & BR_KEYTYPE_SIGN) != 0
				&& hash_id != 0)
			{
				choices->cipher_suite = st[u][0];
				choices->algo_id = hash_id + 0xFF00;
				return 1;
			}
			break;
		}
	}
	return 0;
}

/*
 * TLS 1.3: ECDSA with P-256/SHA-256, P-384/SHA-384 or P-521/SHA-512 (bits
 * 12 to 14); the curve of the key decides.
 */
static int
se_choose13(const br_ssl_server_policy_class **pctx,
	const br_ssl_server_context *cc, uint32_t sig_algs,
	br_ssl_server_choices *choices)
{
	br_ssl_server_policy_ec_context *pc;
	int h;

	pc = (br_ssl_server_policy_ec_context *)pctx;
	if ((pc->allowed_usages & BR_KEYTYPE_SIGN) == 0) {
		return 0;
	}
	switch (pc->sk->curve) {
	case BR_EC_secp256r1: h = 4; break;
	case BR_EC_secp384r1: h = 5; break;
	case BR_EC_secp521r1: h = 6; break;
	default:
		return 0;
	}
	if (((sig_algs >> (8 + h)) & 1) == 0
		|| br_multihash_getimpl(&cc->eng.mhash, h) == NULL)
	{
		return 0;
	}
	choices->algo_id = (h << 8) | 3;
	choices->chain = pc->chain;
	choices->chain_len = pc->chain_len;
	return 1;
}

static size_t
se_do_sign13(const br_ssl_server_policy_class **pctx,
	const br_hash_class *hf, const br_prng_class **rng,
	const unsigned char *hv, size_t hv_len,
	unsigned char *sig, size_t sig_len)
{
	br_ssl_server_policy_ec_context *pc;
	unsigned char tmp[64];

	(void)rng;
	pc = (br_ssl_server_policy_ec_context *)pctx;
	if (hv_len > sizeof tmp || sig_len < 139) {
		return 0;
	}
	memcpy(tmp, hv, hv_len);
	return pc->iecdsa(pc->iec, hf, tmp, pc->sk, sig);
}

static uint32_t
se_do_keyx(const br_ssl_server_policy_class **pctx,
	unsigned char *data, size_t *len)
{
	br_ssl_server_policy_ec_context *pc;
	uint32_t r;
	size_t xoff, xlen;

	pc = (br_ssl_server_policy_ec_context *)pctx;
	r = pc->iec->mul(data, *len, pc->sk->x, pc->sk->xlen, pc->sk->curve);
	xoff = pc->iec->xoff(pc->sk->curve, &xlen);
	memmove(data, data + xoff, xlen);
	*len = xlen;
	return r;
}

static size_t
se_do_sign(const br_ssl_server_policy_class **pctx,
	unsigned algo_id, unsigned char *data, size_t hv_len, size_t len)
{
	br_ssl_server_policy_ec_context *pc;
	unsigned char hv[64];
	const br_hash_class *hc;

	algo_id &= 0xFF;
	pc = (br_ssl_server_policy_ec_context *)pctx;
	hc = br_multihash_getimpl(pc->mhash, algo_id);
	if (hc == NULL) {
		return 0;
	}
	memcpy(hv, data, hv_len);
	if (len < 139) {
		return 0;
	}
	return pc->iecdsa(pc->iec, hc, hv, pc->sk, data);
}

static const br_ssl_server_policy_class se_policy_vtable = {
	sizeof(br_ssl_server_policy_ec_context),
	se_choose,
	se_do_keyx,
	se_do_sign,
	se_choose13,
	se_do_sign13
};

/* see bearssl_ssl.h */
void
br_ssl_server_set_single_ec(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_ec_private_key *sk, unsigned allowed_usages,
	unsigned cert_issuer_key_type,
	const br_ec_impl *iec, br_ecdsa_sign iecdsa)
{
	cc->chain_handler.single_ec.vtable = &se_policy_vtable;
	cc->chain_handler.single_ec.chain = chain;
	cc->chain_handler.single_ec.chain_len = chain_len;
	cc->chain_handler.single_ec.sk = sk;
	cc->chain_handler.single_ec.allowed_usages = allowed_usages;
	cc->chain_handler.single_ec.cert_issuer_key_type = cert_issuer_key_type;
	cc->chain_handler.single_ec.mhash = &cc->eng.mhash;
	cc->chain_handler.single_ec.iec = iec;
	cc->chain_handler.single_ec.iecdsa = iecdsa;
	cc->policy_vtable = &cc->chain_handler.single_ec.vtable;
}
