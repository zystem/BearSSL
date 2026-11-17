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
 * TLS 1.3 record protection with ChaCha20+Poly1305 (RFC 8446, section
 * 5.2 and RFC 8439). Nonce: 12-byte static IV XOR the 64-bit sequence
 * number (big-endian, left-padded). Additional data: the 5-byte record
 * header (type 23, version 0x0303, length of the encrypted record).
 */

static void
gen_chapol13_init(br_sslrec13_chapol_context *cc,
	br_chacha20_run ichacha, br_poly1305_run ipoly,
	const void *key, const void *iv)
{
	cc->seq = 0;
	cc->ichacha = ichacha;
	cc->ipoly = ipoly;
	memcpy(cc->key, key, sizeof cc->key);
	memcpy(cc->iv, iv, sizeof cc->iv);
}

/*
 * Encrypt or decrypt 'len' bytes in place, and compute the tag. 'rlen'
 * is the length of the whole encrypted record (for the header).
 */
static void
chapol13_process(br_sslrec13_chapol_context *cc, size_t rlen,
	void *data, size_t len, void *tag, int encrypt, unsigned char *aad)
{
	unsigned char nonce[12];
	uint64_t seq;
	size_t u;

	seq = cc->seq ++;
	aad[0] = 23;
	aad[1] = 0x03;
	aad[2] = 0x03;
	br_enc16be(aad + 3, (unsigned)rlen);
	memcpy(nonce, cc->iv, 12);
	for (u = 0; u < 8; u ++) {
		nonce[11 - u] ^= (unsigned char)seq;
		seq >>= 8;
	}
	cc->ipoly(cc->key, nonce, data, len, aad, 5,
		tag, cc->ichacha, encrypt);
}

static void
in_chapol13_init(br_sslrec13_chapol_context *cc,
	br_chacha20_run ichacha, br_poly1305_run ipoly,
	const void *key, const void *iv)
{
	cc->vtable.in = &br_sslrec13_in_chapol_vtable;
	gen_chapol13_init(cc, ichacha, ipoly, key, iv);
}

static void
out_chapol13_init(br_sslrec13_chapol_context *cc,
	br_chacha20_run ichacha, br_poly1305_run ipoly,
	const void *key, const void *iv)
{
	cc->vtable.out = &br_sslrec13_out_chapol_vtable;
	gen_chapol13_init(cc, ichacha, ipoly, key, iv);
}

static int
chapol13_check_length(const br_sslrec13_chapol_context *cc, size_t rlen)
{
	(void)cc;
	return rlen >= 17 && rlen <= (16384 + 256);
}

static unsigned char *
chapol13_decrypt(br_sslrec13_chapol_context *cc,
	void *data, size_t *data_len, int *inner_type)
{
	unsigned char *buf;
	unsigned char tag[16], aad[5];
	size_t len, u;
	unsigned bad;

	buf = data;
	len = *data_len - 16;
	chapol13_process(cc, *data_len, buf, len, tag, 0, aad);
	bad = 0;
	for (u = 0; u < 16; u ++) {
		bad |= tag[u] ^ buf[len + u];
	}
	if (bad) {
		return NULL;
	}

	/*
	 * Remove zero padding: the inner type is the last non-zero byte.
	 */
	while (len > 0 && buf[len - 1] == 0) {
		len --;
	}
	if (len == 0) {
		return NULL;
	}
	len --;
	if (len > 16384) {
		return NULL;
	}
	*inner_type = buf[len];
	*data_len = len;
	return buf;
}

/* see bearssl_tls13.h */
const br_sslrec13_in_chapol_class br_sslrec13_in_chapol_vtable = {
	{
		sizeof(br_sslrec13_chapol_context),
		(int (*)(const br_sslrec13_in_class *const *, size_t))
			&chapol13_check_length,
		(unsigned char *(*)(const br_sslrec13_in_class **,
			void *, size_t *, int *))
			&chapol13_decrypt
	},
	(void (*)(const br_sslrec13_in_chapol_class **,
		br_chacha20_run, br_poly1305_run,
		const void *, const void *))
		&in_chapol13_init
};

static void
chapol13_max_plaintext(const br_sslrec13_chapol_context *cc,
	size_t *start, size_t *end)
{
	size_t len;

	(void)cc;
	len = *end - *start - 17;
	if (len > 16384) {
		len = 16384;
	}
	*end = *start + len;
}

static unsigned char *
chapol13_encrypt(br_sslrec13_chapol_context *cc,
	int inner_type, void *data, size_t *data_len)
{
	unsigned char *buf;
	unsigned char aad[5];
	size_t len, clen;

	buf = data;
	len = *data_len;
	buf[len] = (unsigned char)inner_type;
	clen = len + 1;
	chapol13_process(cc, clen + 16, buf, clen, buf + clen, 1, aad);
	buf -= 5;
	memcpy(buf, aad, 5);
	*data_len = clen + 16 + 5;
	return buf;
}

/* see bearssl_tls13.h */
const br_sslrec13_out_chapol_class br_sslrec13_out_chapol_vtable = {
	{
		sizeof(br_sslrec13_chapol_context),
		(void (*)(const br_sslrec13_out_class *const *,
			size_t *, size_t *))
			&chapol13_max_plaintext,
		(unsigned char *(*)(const br_sslrec13_out_class **,
			int, void *, size_t *))
			&chapol13_encrypt
	},
	(void (*)(const br_sslrec13_out_chapol_class **,
		br_chacha20_run, br_poly1305_run,
		const void *, const void *))
		&out_chapol13_init
};
