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
 * TLS 1.3 record protection with AES-GCM (RFC 8446, section 5.2).
 *
 * Nonce: 12-byte static IV XOR the 64-bit sequence number, big-endian,
 * left-padded with zeros. Additional data: the 5-byte record header
 * (type 23, version 0x0303, length of the encrypted record).
 */

static void
gen_gcm13_init(br_sslrec13_gcm_context *cc,
	const br_block_ctr_class *bc_impl,
	const void *key, size_t key_len,
	br_ghash gh_impl,
	const void *iv)
{
	unsigned char tmp[12];

	cc->seq = 0;
	bc_impl->init(&cc->bc.vtable, key, key_len);
	cc->gh = gh_impl;
	memcpy(cc->iv, iv, sizeof cc->iv);
	memset(cc->h, 0, sizeof cc->h);
	memset(tmp, 0, sizeof tmp);
	bc_impl->run(&cc->bc.vtable, tmp, 0, cc->h, sizeof cc->h);
}

static void
in_gcm13_init(br_sslrec13_gcm_context *cc,
	const br_block_ctr_class *bc_impl,
	const void *key, size_t key_len,
	br_ghash gh_impl,
	const void *iv)
{
	cc->vtable.in = &br_sslrec13_in_gcm_vtable;
	gen_gcm13_init(cc, bc_impl, key, key_len, gh_impl, iv);
}

static void
out_gcm13_init(br_sslrec13_gcm_context *cc,
	const br_block_ctr_class *bc_impl,
	const void *key, size_t key_len,
	br_ghash gh_impl,
	const void *iv)
{
	cc->vtable.out = &br_sslrec13_out_gcm_vtable;
	gen_gcm13_init(cc, bc_impl, key, key_len, gh_impl, iv);
}

/*
 * Compute the nonce for the current sequence number, and the header
 * (additional data) for an encrypted record of 'rlen' bytes. The
 * sequence number is incremented.
 */
static void
make_nonce_aad(br_sslrec13_gcm_context *cc, size_t rlen,
	unsigned char *nonce, unsigned char *aad)
{
	uint64_t seq;
	size_t u;

	seq = cc->seq ++;
	memcpy(nonce, cc->iv, 12);
	for (u = 0; u < 8; u ++) {
		nonce[11 - u] ^= (unsigned char)seq;
		seq >>= 8;
	}
	aad[0] = 23;
	aad[1] = 0x03;
	aad[2] = 0x03;
	br_enc16be(aad + 3, (unsigned)rlen);
}

/*
 * Compute the GCM tag over 'data' (ciphertext, 'len' bytes). The value
 * written in 'tag' still has to be XORed with the keystream block of
 * counter 1.
 */
static void
do_tag(br_sslrec13_gcm_context *cc, const unsigned char *aad,
	const void *data, size_t len, void *tag)
{
	unsigned char footer[16];

	br_enc64be(footer, (uint64_t)5 << 3);
	br_enc64be(footer + 8, (uint64_t)len << 3);
	memset(tag, 0, 16);
	cc->gh(tag, cc->h, aad, 5);
	cc->gh(tag, cc->h, data, len);
	cc->gh(tag, cc->h, footer, sizeof footer);
}

static int
gcm13_check_length(const br_sslrec13_gcm_context *cc, size_t rlen)
{
	/*
	 * Overhead: 16 bytes of tag and at least 1 byte of inner type.
	 * Maximum: the whole inner plaintext (content, type and padding)
	 * is at most 2^14 + 1 bytes (RFC 8446, sections 5.2 and 5.4), plus
	 * the tag. The RFC limit of 2^14 + 256 for the record is for
	 * ciphers with a larger overhead and does not let padding grow
	 * the inner plaintext beyond 2^14 + 1.
	 */
	(void)cc;
	return rlen >= 17 && rlen <= (16384 + 1 + 16);
}

static unsigned char *
gcm13_decrypt(br_sslrec13_gcm_context *cc,
	void *data, size_t *data_len, int *inner_type)
{
	unsigned char *buf;
	unsigned char nonce[12], aad[5], tag[16], mask[16];
	size_t len, u;
	uint32_t bad;

	buf = data;
	len = *data_len - 16;
	make_nonce_aad(cc, *data_len, nonce, aad);

#ifdef BR_TLS13_FUZZ
	/*
	 * Fuzzing build only: the record body is taken as the plaintext, so
	 * that a fuzzer controls it without knowing the keys; there is no tag.
	 */
	(void)nonce;
	(void)tag;
	(void)mask;
	(void)u;
	(void)bad;
#else
	/*
	 * Tag first (on the ciphertext), then decryption in place.
	 */
	do_tag(cc, aad, buf, len, tag);
	memset(mask, 0, sizeof mask);
	cc->bc.vtable->run(&cc->bc.vtable, nonce, 2, buf, len);
	cc->bc.vtable->run(&cc->bc.vtable, nonce, 1, mask, sizeof mask);
	bad = 0;
	for (u = 0; u < 16; u ++) {
		bad |= (tag[u] ^ mask[u]) ^ buf[len + u];
	}
	if (bad) {
		return NULL;
	}
#endif

	/*
	 * Remove zero padding: the inner type is the last non-zero byte.
	 */
	u = br_tls13_find_type(buf, len);
	if (u == (size_t)-1 || u > 16384) {
		return NULL;
	}
	len = u;
	*inner_type = buf[len];
	*data_len = len;
	return buf;
}

/* see bearssl_tls13.h */
const br_sslrec13_in_gcm_class br_sslrec13_in_gcm_vtable = {
	{
		sizeof(br_sslrec13_gcm_context),
		(int (*)(const br_sslrec13_in_class *const *, size_t))
			&gcm13_check_length,
		(unsigned char *(*)(const br_sslrec13_in_class **,
			void *, size_t *, int *))
			&gcm13_decrypt
	},
	(void (*)(const br_sslrec13_in_gcm_class **,
		const br_block_ctr_class *, const void *, size_t,
		br_ghash, const void *))
		&in_gcm13_init
};

static void
gcm13_max_plaintext(const br_sslrec13_gcm_context *cc,
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
gcm13_encrypt(br_sslrec13_gcm_context *cc,
	int inner_type, void *data, size_t *data_len)
{
	unsigned char *buf;
	unsigned char nonce[12], aad[5], mask[16];
	size_t len, clen, u;

	buf = data;
	len = *data_len;
	buf[len] = (unsigned char)inner_type;
	clen = len + 1;
	make_nonce_aad(cc, clen + 16, nonce, aad);

	memset(mask, 0, sizeof mask);
	cc->bc.vtable->run(&cc->bc.vtable, nonce, 2, buf, clen);
	cc->bc.vtable->run(&cc->bc.vtable, nonce, 1, mask, sizeof mask);
	do_tag(cc, aad, buf, clen, buf + clen);
	for (u = 0; u < 16; u ++) {
		buf[clen + u] ^= mask[u];
	}

	buf -= 5;
	memcpy(buf, aad, 5);
	*data_len = clen + 16 + 5;
	return buf;
}

/* see bearssl_tls13.h */
const br_sslrec13_out_gcm_class br_sslrec13_out_gcm_vtable = {
	{
		sizeof(br_sslrec13_gcm_context),
		(void (*)(const br_sslrec13_out_class *const *,
			size_t *, size_t *))
			&gcm13_max_plaintext,
		(unsigned char *(*)(const br_sslrec13_out_class **,
			int, void *, size_t *))
			&gcm13_encrypt
	},
	(void (*)(const br_sslrec13_out_gcm_class **,
		const br_block_ctr_class *, const void *, size_t,
		br_ghash, const void *))
		&out_gcm13_init
};
