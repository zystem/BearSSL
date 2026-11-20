/*
 * A fixed TLS 1.3 session for the fuzzing targets and the seed generator:
 * a ticket of 32 bytes and a PSK for TLS_AES_128_GCM_SHA256.
 */
static void
fuzz_session(br_ssl_session_parameters *sp)
{
	memset(sp, 0, sizeof *sp);
	memset(sp->session_id, 0x42, 32);
	sp->session_id_len = 0;
	sp->version = BR_TLS13;
	sp->cipher_suite = 0x1301;
	memset(sp->master_secret, 0x07, 32);
	sp->ticket_len = 32;
	memset(sp->ticket, 0x42, 32);
	sp->ticket_age_add = 0x01020304;
	sp->ticket_lifetime = 3600;
}

/* The same session as a server's cache entry (the ticket is the ID). */
static void
fuzz_server_cache(br_ssl_server_context *sc, br_ssl_session_cache_lru *lru,
	unsigned char *buf, size_t buflen)
{
	br_ssl_session_parameters sp;

	fuzz_session(&sp);
	sp.session_id_len = 32;
	sp.ticket_len = 0;
	br_ssl_session_cache_lru_init(lru, buf, buflen);
	br_ssl_server_set_cache(sc, &lru->vtable);
	lru->vtable->save(&lru->vtable, sc, &sp);
}
