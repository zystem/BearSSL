/*
 * TLS 1.3 session resumption against a server: connects twice, the second
 * time with the ticket that the first connection brought. For the
 * interoperability checks (the server is OpenSSL, GnuTLS, Go or ours).
 *
 *   cc -O2 -Isrc -Iinc test/resume_client.c build/libbearssl.a -o resume_client
 *   resume_client HOST PORT [-CA cert.pem-DER?]
 *
 * The server certificate is not validated (this is only a protocol check);
 * the program prints, for each connection, the version, the suite, whether the
 * session was resumed and the size of the ticket received. Exit status 0 if
 * the second connection resumed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "bearssl.h"

static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
	for (;;) {
		ssize_t r = read(*(int *)ctx, buf, len);

		if (r < 0) {
			continue;
		}
		return (int)r;
	}
}

static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	for (;;) {
		ssize_t r = write(*(int *)ctx, buf, len);

		if (r < 0) {
			continue;
		}
		return (int)r;
	}
}

/*
 * An X.509 class that accepts any chain and returns the key of the first
 * certificate (there is no validation: this program tests the protocol).
 */
typedef struct {
	const br_x509_class *vtable;
	br_x509_decoder_context dec;
	int first;
} anyx509;

static void
a_start_chain(const br_x509_class **ctx, const char *name)
{
	anyx509 *a = (anyx509 *)ctx;

	(void)name;
	a->first = 1;
}
static void
a_start_cert(const br_x509_class **ctx, uint32_t len)
{
	anyx509 *a = (anyx509 *)ctx;

	(void)len;
	if (a->first) {
		br_x509_decoder_init(&a->dec, NULL, NULL);
	}
}
static void
a_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
	anyx509 *a = (anyx509 *)ctx;

	if (a->first) {
		br_x509_decoder_push(&a->dec, buf, len);
	}
}
static void
a_end_cert(const br_x509_class **ctx)
{
	((anyx509 *)ctx)->first = 0;
}
static unsigned
a_end_chain(const br_x509_class **ctx)
{
	return br_x509_decoder_last_error(&((anyx509 *)ctx)->dec);
}
static const br_x509_pkey *
a_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
	if (usages != NULL) {
		*usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
	}
	return br_x509_decoder_get_pkey(&((anyx509 *)ctx)->dec);
}
static const br_x509_class any_class = {
	sizeof(anyx509), a_start_chain, a_start_cert, a_append, a_end_cert,
	a_end_chain, a_get_pkey
};

static br_ssl_client_context cc;
static br_x509_minimal_context xc;
static anyx509 ax;
static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];

static int
connect_to(const char *host, int port)
{
	struct sockaddr_in sa;
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	inet_pton(AF_INET, host, &sa.sin_addr);
	if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		perror("connect");
		exit(2);
	}
	return fd;
}

int
main(int argc, char **argv)
{
	br_ssl_session_parameters saved;
	int round, resumed2 = 0;

	if (argc < 3) {
		fprintf(stderr, "usage: resume_client HOST PORT\n");
		return 2;
	}
	memset(&saved, 0, sizeof saved);
	for (round = 0; round < 2; round ++) {
		int fd = connect_to(argv[1], atoi(argv[2]));
		br_sslio_context ioc;
		unsigned char buf[2048];
		int n;
		br_ssl_engine_context *eng = &cc.eng;
		static const char *protos[] = { "h2" };
		br_ssl_session_parameters sp;

		br_ssl_client_init_full(&cc, &xc, NULL, 0);
		ax.vtable = &any_class;
		br_ssl_engine_set_x509(eng, &ax.vtable);
		br_ssl_engine_set_versions(eng, BR_TLS12, BR_TLS13);
		{
			static const uint16_t suites[] = { 0x1301, 0x1302, 0x1303 };

			br_ssl_engine_set_suites(eng, suites, 3);
		}
		(void)protos;
		br_ssl_engine_set_buffer(eng, iobuf, sizeof iobuf, 1);
		if (round > 0) {
			br_ssl_engine_set_session_parameters(eng, &saved);
		}
		br_ssl_client_reset(&cc, "localhost", round > 0);
		br_sslio_init(&ioc, eng, sock_read, &fd, sock_write, &fd);
		br_sslio_write_all(&ioc, "GET / HTTP/1.0\r\n\r\n", 18);
		br_sslio_flush(&ioc);
		n = br_sslio_read(&ioc, buf, sizeof buf);
		br_ssl_engine_get_session_parameters(eng, &sp);
		printf("connection %d: %s, suite %04x, %s, %d bytes read, "
			"ticket %u bytes, error %d\n",
			round + 1, sp.version == BR_TLS13 ? "TLS 1.3" : "other",
			sp.cipher_suite,
			eng->tls13_resumed == 2 ? "RESUMED" : "full handshake", n,
			(unsigned)sp.ticket_len, br_ssl_engine_last_error(eng));
		if (round == 1 && eng->tls13_resumed == 2) {
			resumed2 = 1;
		}
		saved = sp;
		br_sslio_close(&ioc);
		close(fd);
	}
	return resumed2 ? 0 : 1;
}
