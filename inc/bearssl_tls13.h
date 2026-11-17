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

#ifndef BR_BEARSSL_TLS13_H__
#define BR_BEARSSL_TLS13_H__

#include <stddef.h>
#include <stdint.h>

#include "bearssl_hash.h"
#include "bearssl_block.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \file bearssl_tls13.h
 *
 * # TLS 1.3 Key Schedule
 *
 * This file documents the TLS 1.3 key schedule (RFC 8446, section 7.1)
 * on top of HMAC. It is the first building block of the TLS 1.3 support
 * of this fork; the handshake itself is not implemented yet.
 *
 * The hash function is the one of the cipher suite: SHA-256 or SHA-384
 * (`br_sha256_vtable` or `br_sha384_vtable`). All "secret" and "traffic
 * secret" values are as long as the hash output (32 or 48 bytes).
 *
 * The functions take the secrets as pointers to buffers of at least the
 * hash output length, and write outputs of exactly the documented
 * length. They do not allocate memory. A function that is called with a
 * hash function other than SHA-256 or SHA-384, with a label longer than
 * 249 bytes, or with a context longer than 255 bytes, has an undefined
 * result: the caller (the TLS engine) passes constant labels only.
 *
 * Typical use, for the schedule of one connection:
 *
 *  - `br_tls13_ks_init()` with the PSK (or no PSK): computes the
 *    "early secret".
 *  - `br_tls13_ks_advance()` with no input (resumption without key
 *    exchange is not used) or with the (EC)DHE shared secret: moves
 *    to the "handshake secret".
 *  - `br_tls13_derive_secret()` with labels "c hs traffic" and
 *    "s hs traffic" and the transcript hash up to the ServerHello.
 *  - `br_tls13_ks_advance()` again, with no input: moves to the
 *    "master secret".
 *  - `br_tls13_derive_secret()` with labels "c ap traffic" and
 *    "s ap traffic" and the transcript hash up to the server Finished.
 *  - `br_tls13_traffic_keys()` for the record keys and IVs of each
 *    traffic secret, and `br_tls13_finished_key()` for the Finished
 *    messages.
 */

/**
 * \brief Largest hash output length (SHA-384), in bytes.
 */
#define BR_TLS13_MAX_HASH_LEN   48

/**
 * \brief Key schedule context.
 *
 * It holds the current secret (early, handshake or master secret) and
 * the hash function. Contents should be considered opaque.
 */
typedef struct {
	/** \brief Hash function (vtable). */
	const br_hash_class *dig;
	/** \brief Current secret. */
	unsigned char secret[BR_TLS13_MAX_HASH_LEN];
} br_tls13_ks_context;

/**
 * \brief Initialise a key schedule: compute the early secret.
 *
 * The early secret is `HKDF-Extract(0, PSK)`, where a missing PSK is
 * a string of zero bytes of the hash output length.
 *
 * \param kc        key schedule context.
 * \param dig       hash function (`br_sha256_vtable` or `br_sha384_vtable`).
 * \param psk       PSK, or `NULL` when there is none.
 * \param psk_len   PSK length (in bytes; ignored when `psk` is `NULL`).
 */
void br_tls13_ks_init(br_tls13_ks_context *kc, const br_hash_class *dig,
	const void *psk, size_t psk_len);

/**
 * \brief Move to the next secret of the key schedule.
 *
 * The new secret is
 * `HKDF-Extract(Derive-Secret(current, "derived", ""), ikm)`: from the
 * early secret to the handshake secret (with the (EC)DHE shared secret
 * as `ikm`), then from the handshake secret to the master secret (with
 * no input).
 *
 * \param kc        key schedule context.
 * \param ikm       input keying material, or `NULL` for a string of zero
 *                  bytes of the hash output length.
 * \param ikm_len   input length (in bytes; ignored when `ikm` is `NULL`).
 */
void br_tls13_ks_advance(br_tls13_ks_context *kc,
	const void *ikm, size_t ikm_len);

/**
 * \brief `HKDF-Expand-Label` (RFC 8446, section 7.1).
 *
 * The label is given without the "tls13 " prefix, which is added here.
 * Only a single HKDF block is produced, so `out_len` must not be larger
 * than the hash output length; that is enough for all uses in TLS 1.3.
 *
 * \param dig           hash function.
 * \param secret        secret (hash output length bytes).
 * \param label         label, as a C string, without the "tls13 " prefix.
 * \param context       context value (may be `NULL` if `context_len` is 0).
 * \param context_len   context length (in bytes, at most 255).
 * \param out           output buffer.
 * \param out_len       output length (in bytes).
 */
void br_tls13_expand_label(const br_hash_class *dig, const void *secret,
	const char *label, const void *context, size_t context_len,
	void *out, size_t out_len);

/**
 * \brief `Derive-Secret` (RFC 8446, section 7.1).
 *
 * It is `HKDF-Expand-Label(secret, label, transcript_hash, Hash.length)`.
 * The caller supplies the transcript hash (for the empty transcript, the
 * hash of the empty string).
 *
 * \param dig               hash function.
 * \param secret            secret (hash output length bytes).
 * \param label             label (without the "tls13 " prefix).
 * \param transcript_hash   transcript hash (hash output length bytes).
 * \param out               output buffer (hash output length bytes).
 */
void br_tls13_derive_secret(const br_hash_class *dig, const void *secret,
	const char *label, const void *transcript_hash, void *out);

/**
 * \brief Derive the record protection key and IV from a traffic secret.
 *
 * `key` is `HKDF-Expand-Label(secret, "key", "", key_len)` and `iv` is
 * `HKDF-Expand-Label(secret, "iv", "", 12)`.
 *
 * \param dig       hash function.
 * \param secret    traffic secret (hash output length bytes).
 * \param key_len   key length (16 or 32, and not above the hash length).
 * \param key       output buffer for the key.
 * \param iv        output buffer for the IV (12 bytes).
 */
void br_tls13_traffic_keys(const br_hash_class *dig, const void *secret,
	size_t key_len, void *key, void *iv);

/**
 * \brief Derive the key of the Finished message from a traffic secret.
 *
 * It is `HKDF-Expand-Label(secret, "finished", "", Hash.length)`; the
 * traffic secret is the handshake traffic secret of the sender.
 *
 * \param dig      hash function.
 * \param secret   handshake traffic secret (hash output length bytes).
 * \param out      output buffer (hash output length bytes).
 */
void br_tls13_finished_key(const br_hash_class *dig, const void *secret,
	void *out);

/**
 * \brief Compute the next application traffic secret (KeyUpdate).
 *
 * It is `HKDF-Expand-Label(secret, "traffic upd", "", Hash.length)`.
 * `out` may be the same buffer as `secret`.
 *
 * \param dig      hash function.
 * \param secret   current traffic secret (hash output length bytes).
 * \param out      output buffer (hash output length bytes).
 */
void br_tls13_next_traffic_secret(const br_hash_class *dig,
	const void *secret, void *out);

/* ===================================================================== */

/*
 * # TLS 1.3 Record Protection
 *
 * In TLS 1.3 (RFC 8446, section 5) every encrypted record has the outer
 * type 23 and the legacy version 0x0303. The cleartext is
 * `content || inner_type || zero padding`, and the AEAD additional data
 * is the 5-byte record header (23, 0x0303, length of the encrypted
 * record, which includes the 16-byte tag). The nonce is the static
 * 12-byte IV XORed with the 64-bit record sequence number (left padded
 * with zeros), and the sequence number restarts at 0 with every new
 * key.
 *
 * The vtables below follow the shape of the TLS 1.2 record codecs
 * (`br_sslrec_in_class`, `br_sslrec_out_class`) but have their own
 * types, because the decryption must return the inner content type and
 * because there is no record type or version to pass in.
 *
 * Limits: the encryption side does not add padding, and does not
 * count records: the engine must switch to new keys (KeyUpdate) well
 * before the limit of the AEAD (about 2^24 records for AES-GCM).
 */

/**
 * \brief Decryption engine for TLS 1.3 records.
 *
 * The decryption engine verifies the tag, decrypts, removes the padding
 * and the inner content type, and keeps the record sequence number.
 */
typedef struct br_sslrec13_in_class_ br_sslrec13_in_class;
struct br_sslrec13_in_class_ {
	/**
	 * \brief Context size (in bytes).
	 */
	size_t context_size;

	/**
	 * \brief Test validity of the incoming record length.
	 *
	 * The length is the one in the record header (cleartext plus
	 * inner type plus tag). It is valid between 17 and 16640 bytes.
	 *
	 * \param ctx          decryption engine context.
	 * \param record_len   incoming record length.
	 * \return  1 for a valid length, 0 otherwise.
	 */
	int (*check_length)(const br_sslrec13_in_class *const *ctx,
		size_t record_len);

	/**
	 * \brief Decrypt the incoming record.
	 *
	 * The caller must have checked that the outer record type is 23 and
	 * the length with `check_length()`. Decryption is done in place.
	 * `*len` is updated with the content length (without the inner
	 * type, the padding and the tag), `*inner_type` receives the inner
	 * content type, and the address of the first content byte is
	 * returned. A correct record with empty content gives `*len` set
	 * to 0 and a non-`NULL` pointer.
	 *
	 * `NULL` is returned if the tag is wrong, if the cleartext has no
	 * non-zero byte (no inner type), or if the content is longer than
	 * 16384 bytes. The caller must then send an alert and close.
	 *
	 * \param ctx          decryption engine context.
	 * \param payload      address of the encrypted payload.
	 * \param len          pointer to the payload length (updated).
	 * \param inner_type   output for the inner content type.
	 * \return  pointer to the content, or `NULL` on error.
	 */
	unsigned char *(*decrypt)(const br_sslrec13_in_class **ctx,
		void *payload, size_t *len, int *inner_type);
};

/**
 * \brief Encryption engine for TLS 1.3 records.
 */
typedef struct br_sslrec13_out_class_ br_sslrec13_out_class;
struct br_sslrec13_out_class_ {
	/**
	 * \brief Context size (in bytes).
	 */
	size_t context_size;

	/**
	 * \brief Compute maximum plaintext sizes and offsets.
	 *
	 * As for TLS 1.2 (`br_sslrec_out_class`): `*start` and `*end`
	 * designate the free area of the outgoing buffer, which is
	 * preceded by a 5-byte space for the record header. On return,
	 * the area is the one for the content, with room for the inner
	 * type byte and the tag, and at most 16384 bytes long.
	 *
	 * \param ctx     encryption engine context.
	 * \param start   pointer to start of plaintext offset (updated).
	 * \param end     pointer to end of plaintext offset (updated).
	 */
	void (*max_plaintext)(const br_sslrec13_out_class *const *ctx,
		size_t *start, size_t *end);

	/**
	 * \brief Perform record encryption.
	 *
	 * The content is at `plaintext`, preceded by 5 free bytes (for the
	 * header) and followed by at least 17 free bytes (inner type and
	 * tag). `*len` is the content length (at most 16384), and is updated
	 * with the total record length, header included. The address of the
	 * record header is returned.
	 *
	 * \param ctx          encryption engine context.
	 * \param inner_type   inner content type (22 for handshake, etc).
	 * \param plaintext    address of the content.
	 * \param len          pointer to the content length (updated).
	 * \return  pointer to the start of the record.
	 */
	unsigned char *(*encrypt)(const br_sslrec13_out_class **ctx,
		int inner_type, void *plaintext, size_t *len);
};

/**
 * \brief Decryption engine class for TLS 1.3 records, AES-GCM.
 */
typedef struct br_sslrec13_in_gcm_class_ br_sslrec13_in_gcm_class;
struct br_sslrec13_in_gcm_class_ {
	/** \brief Superclass, as first vtable field. */
	br_sslrec13_in_class inner;

	/**
	 * \brief Engine initialisation method; it sets the vtable field
	 * and the sequence number to 0.
	 *
	 * \param ctx       context to initialise.
	 * \param bc_impl   block cipher implementation (CTR).
	 * \param key       AES key.
	 * \param key_len   AES key length (16 or 32 bytes).
	 * \param gh_impl   GHASH implementation.
	 * \param iv        static IV (12 bytes).
	 */
	void (*init)(const br_sslrec13_in_gcm_class **ctx,
		const br_block_ctr_class *bc_impl,
		const void *key, size_t key_len,
		br_ghash gh_impl,
		const void *iv);
};

/**
 * \brief Encryption engine class for TLS 1.3 records, AES-GCM.
 */
typedef struct br_sslrec13_out_gcm_class_ br_sslrec13_out_gcm_class;
struct br_sslrec13_out_gcm_class_ {
	/** \brief Superclass, as first vtable field. */
	br_sslrec13_out_class inner;

	/** \brief Engine initialisation method (see the decryption class). */
	void (*init)(const br_sslrec13_out_gcm_class **ctx,
		const br_block_ctr_class *bc_impl,
		const void *key, size_t key_len,
		br_ghash gh_impl,
		const void *iv);
};

/** \brief Static, constant vtable for TLS 1.3 record decryption, AES-GCM. */
extern const br_sslrec13_in_gcm_class br_sslrec13_in_gcm_vtable;

/** \brief Static, constant vtable for TLS 1.3 record encryption, AES-GCM. */
extern const br_sslrec13_out_gcm_class br_sslrec13_out_gcm_vtable;

/**
 * \brief Context for TLS 1.3 record processing with AES-GCM.
 *
 * The same structure is used for both directions. The first field is
 * the vtable pointer; after initialisation the context is used through
 * `&ctx.vtable.in` or `&ctx.vtable.out`.
 */
typedef struct {
	/** \brief Pointer to vtable. */
	union {
		const void *gen;
		const br_sslrec13_in_gcm_class *in;
		const br_sslrec13_out_gcm_class *out;
	} vtable;
#ifndef BR_DOXYGEN_IGNORE
	uint64_t seq;
	union {
		const br_block_ctr_class *vtable;
		br_aes_gen_ctr_keys aes;
	} bc;
	br_ghash gh;
	unsigned char iv[12];
	unsigned char h[16];
#endif
} br_sslrec13_gcm_context;

/**
 * \brief Decryption engine class for TLS 1.3 records, ChaCha20+Poly1305.
 */
typedef struct br_sslrec13_in_chapol_class_ br_sslrec13_in_chapol_class;
struct br_sslrec13_in_chapol_class_ {
	/** \brief Superclass, as first vtable field. */
	br_sslrec13_in_class inner;

	/**
	 * \brief Engine initialisation method; it sets the vtable field
	 * and the sequence number to 0.
	 *
	 * \param ctx       context to initialise.
	 * \param ichacha   ChaCha20 implementation.
	 * \param ipoly     Poly1305 implementation.
	 * \param key       key (32 bytes).
	 * \param iv        static IV (12 bytes).
	 */
	void (*init)(const br_sslrec13_in_chapol_class **ctx,
		br_chacha20_run ichacha, br_poly1305_run ipoly,
		const void *key, const void *iv);
};

/**
 * \brief Encryption engine class for TLS 1.3 records, ChaCha20+Poly1305.
 */
typedef struct br_sslrec13_out_chapol_class_ br_sslrec13_out_chapol_class;
struct br_sslrec13_out_chapol_class_ {
	/** \brief Superclass, as first vtable field. */
	br_sslrec13_out_class inner;

	/** \brief Engine initialisation method (see the decryption class). */
	void (*init)(const br_sslrec13_out_chapol_class **ctx,
		br_chacha20_run ichacha, br_poly1305_run ipoly,
		const void *key, const void *iv);
};

/** \brief Static, constant vtable for TLS 1.3 record decryption, ChaCha20+Poly1305. */
extern const br_sslrec13_in_chapol_class br_sslrec13_in_chapol_vtable;

/** \brief Static, constant vtable for TLS 1.3 record encryption, ChaCha20+Poly1305. */
extern const br_sslrec13_out_chapol_class br_sslrec13_out_chapol_vtable;

/**
 * \brief Context for TLS 1.3 record processing with ChaCha20+Poly1305.
 */
typedef struct {
	/** \brief Pointer to vtable. */
	union {
		const void *gen;
		const br_sslrec13_in_chapol_class *in;
		const br_sslrec13_out_chapol_class *out;
	} vtable;
#ifndef BR_DOXYGEN_IGNORE
	uint64_t seq;
	unsigned char key[32];
	unsigned char iv[12];
	br_chacha20_run ichacha;
	br_poly1305_run ipoly;
#endif
} br_sslrec13_chapol_context;

#ifdef __cplusplus
}
#endif

#endif
