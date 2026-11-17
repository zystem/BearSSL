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
 * HMAC over up to three input chunks, with the full-length output.
 * `out` receives br_digest_size(dig) bytes.
 */
static void
hmac3(const br_hash_class *dig, const void *key, size_t key_len,
	const void *a, size_t a_len, const void *b, size_t b_len,
	const void *c, size_t c_len, void *out)
{
	br_hmac_key_context kc;
	br_hmac_context hc;

	br_hmac_key_init(&kc, dig, key, key_len);
	br_hmac_init(&hc, &kc, 0);
	if (a_len > 0) {
		br_hmac_update(&hc, a, a_len);
	}
	if (b_len > 0) {
		br_hmac_update(&hc, b, b_len);
	}
	if (c_len > 0) {
		br_hmac_update(&hc, c, c_len);
	}
	br_hmac_out(&hc, out);
}

/*
 * HKDF-Extract(salt, ikm): HMAC with the salt as key.
 */
static void
extract(const br_hash_class *dig, void *out,
	const void *salt, const void *ikm, size_t ikm_len)
{
	hmac3(dig, salt, br_digest_size(dig), ikm, ikm_len,
		NULL, 0, NULL, 0, out);
}

/* see bearssl_tls13.h */
void
br_tls13_expand_label(const br_hash_class *dig, const void *secret,
	const char *label, const void *context, size_t context_len,
	void *out, size_t out_len)
{
	/*
	 * HkdfLabel (RFC 8446, section 7.1):
	 *   uint16 length;
	 *   opaque label<7..255> = "tls13 " + Label;
	 *   opaque context<0..255>;
	 * followed by the HKDF-Expand block counter (1): only one block is
	 * ever needed, because out_len <= Hash.length.
	 */
	unsigned char hdr[3], lab[255], ctr, ctxlen, t[BR_TLS13_MAX_HASH_LEN];
	br_hmac_key_context kc;
	br_hmac_context hc;
	size_t label_len;

	label_len = strlen(label);
	hdr[0] = (unsigned char)(out_len >> 8);
	hdr[1] = (unsigned char)out_len;
	hdr[2] = (unsigned char)(6 + label_len);
	memcpy(lab, "tls13 ", 6);
	memcpy(lab + 6, label, label_len);
	ctxlen = (unsigned char)context_len;
	ctr = 1;

	br_hmac_key_init(&kc, dig, secret, br_digest_size(dig));
	br_hmac_init(&hc, &kc, 0);
	br_hmac_update(&hc, hdr, 3);
	br_hmac_update(&hc, lab, 6 + label_len);
	br_hmac_update(&hc, &ctxlen, 1);
	if (context_len > 0) {
		br_hmac_update(&hc, context, context_len);
	}
	br_hmac_update(&hc, &ctr, 1);
	br_hmac_out(&hc, t);
	memcpy(out, t, out_len);
}

/* see bearssl_tls13.h */
void
br_tls13_derive_secret(const br_hash_class *dig, const void *secret,
	const char *label, const void *transcript_hash, void *out)
{
	size_t hlen;

	hlen = br_digest_size(dig);
	br_tls13_expand_label(dig, secret, label, transcript_hash, hlen,
		out, hlen);
}

/* see bearssl_tls13.h */
void
br_tls13_ks_init(br_tls13_ks_context *kc, const br_hash_class *dig,
	const void *psk, size_t psk_len)
{
	unsigned char zeros[BR_TLS13_MAX_HASH_LEN];
	size_t hlen;

	hlen = br_digest_size(dig);
	memset(zeros, 0, sizeof zeros);
	if (psk == NULL) {
		psk = zeros;
		psk_len = hlen;
	}
	kc->dig = dig;
	extract(dig, kc->secret, zeros, psk, psk_len);
}

/* see bearssl_tls13.h */
void
br_tls13_ks_advance(br_tls13_ks_context *kc, const void *ikm, size_t ikm_len)
{
	const br_hash_class *dig;
	br_hash_compat_context hc;
	unsigned char zeros[BR_TLS13_MAX_HASH_LEN];
	unsigned char empty[BR_TLS13_MAX_HASH_LEN];
	unsigned char derived[BR_TLS13_MAX_HASH_LEN];
	size_t hlen;

	dig = kc->dig;
	hlen = br_digest_size(dig);
	memset(zeros, 0, sizeof zeros);
	if (ikm == NULL) {
		ikm = zeros;
		ikm_len = hlen;
	}

	/* Hash of the empty string. */
	dig->init(&hc.vtable);
	dig->out(&hc.vtable, empty);

	br_tls13_derive_secret(dig, kc->secret, "derived", empty, derived);
	extract(dig, kc->secret, derived, ikm, ikm_len);
}

/* see bearssl_tls13.h */
void
br_tls13_traffic_keys(const br_hash_class *dig, const void *secret,
	size_t key_len, void *key, void *iv)
{
	br_tls13_expand_label(dig, secret, "key", NULL, 0, key, key_len);
	br_tls13_expand_label(dig, secret, "iv", NULL, 0, iv, 12);
}

/* see bearssl_tls13.h */
void
br_tls13_finished_key(const br_hash_class *dig, const void *secret, void *out)
{
	br_tls13_expand_label(dig, secret, "finished", NULL, 0,
		out, br_digest_size(dig));
}

/* see bearssl_tls13.h */
void
br_tls13_next_traffic_secret(const br_hash_class *dig,
	const void *secret, void *out)
{
	br_tls13_expand_label(dig, secret, "traffic upd", NULL, 0,
		out, br_digest_size(dig));
}
