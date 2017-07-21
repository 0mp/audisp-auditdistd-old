#include <sys/socket.h>

#include <err.h>
#include <netdb.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>

#define	ADIST_PORT	    7878
#define	ADIST_WELCOME_MSG   "ADIST00"

int
tcp_connect(const char *addr)
{
	struct sockaddr_in destaddr;
	int sockfd;
	int ret;
	struct hostent *desthost;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	desthost = gethostbyname(addr);
	if (desthost == NULL)
		return 0;

	destaddr.sin_family = AF_INET;
	destaddr.sin_port = htons(ADIST_PORT);
	destaddr.sin_addr.s_addr = *(long *)(desthost->h_addr);

	ret = connect(sockfd, (struct sockaddr *)&destaddr, sizeof(destaddr));
	if (ret == -1)
		return 0;

	return sockfd;
}

int
main(int argc, char *argv[])
{
	SSL_CTX *sslctx;
	SSL *ssl;
	int tcpfd;
	int ret;

	int opt;
	char *hostname;
	char *server;
	char *password;
	char welcome[8];
	unsigned char rnd[32], hash[32];

	hostname = NULL;
	server = NULL;
	password = NULL;

	while ((opt = getopt(argc, argv, "h:s:p:")) != -1) {
		switch (opt) {
		case 'h':
			/* E.g., "example.org" */
			hostname = &(*optarg);
			fprintf(stderr, "hostname: %s\n", hostname);
			break;
		case 's':
			/* E.g., "192.168.56.101" */
			server = &(*optarg);
			fprintf(stderr, "server: %s\n", server);
			break;
		case 'p':
			/* E.g., "vaabwY+e7+wvc48pqEhtZOq41ssysIz" */
			password = &(*optarg);
			fprintf(stderr, "password: %s\n", password);
			break;
		default:
			/* Ignore. */
			break;
		}
	}
	if (hostname == NULL || server == NULL || password == NULL)
		errx(1, "Usage: %s -h host -s server -p password\n", argv[0]);

	SSL_library_init();

	sslctx = SSL_CTX_new(TLSv1_client_method());
	if (sslctx == NULL)
		err(1, "Failed to create a new SSL_CTX object");

	SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	ssl = SSL_new(sslctx);
	if (ssl == NULL)
		err(1, "Failed to create a new SSL context for a connection");

	tcpfd = tcp_connect(server);
	if (tcpfd == 0)
		err(1, "Failed to establish an underlying TCP connection");

	SSL_set_fd(ssl, tcpfd);

	ret = SSL_connect(ssl);
	if (ret != 1)
		err(1, "Failed to connect over SSL");

	SSL_write(ssl, ADIST_WELCOME_MSG, sizeof(ADIST_WELCOME_MSG));
	SSL_read(ssl, welcome, sizeof(welcome));
	// TODO: Make sure that the received version is supported.
	fprintf(stderr, "Exchanged welcome messages (%s)\n", welcome);

	SSL_write(ssl, hostname, sizeof(hostname));
	fprintf(stderr, "Sent the host name\n");

	/* Challenge */
	SSL_read(ssl, rnd, sizeof(rnd));
	fprintf(stderr, "Received challenge\n");

	if (HMAC(EVP_sha256(), password,
	    (int)strlen(password), rnd, (int)sizeof(rnd), hash,
	    NULL) == NULL) {
		err(1, "Unable to generate a response.");
	}
	SSL_write(ssl, hash, sizeof(rnd));
	fprintf(stderr, "Responded to the challenge\n");

	SSL_free(ssl);
	close(tcpfd);
	SSL_CTX_free(sslctx);

	return (0);
}
