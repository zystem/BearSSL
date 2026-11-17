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

#ifdef __cplusplus
}
#endif

#endif
