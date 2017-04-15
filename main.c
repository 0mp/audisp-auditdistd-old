#include <openssl/ssl.h>
#include <err.h>

int
main(void)
{
	SSL_CTX *sslctx;
	SSL *ssl;
	int tcpfd;

	/*
	 * TODO: Connect to the server?
	 * I am not sure yet how auditdistd connects to the receiving end.
	 */

	SSL_library_init();
	sslctx = SSL_CTX_new(TLSv1_client_method());
	if (sslctx == NULL)
		err(1, "Failed to create a new SSL_CTX object");

	SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	ssl = SSL_new(sslctx);
	if (ssl == NULL)
		err(1, "Failed to create a new SSL structure for a connection");

	/*
	 * TODO: Continue rewriting the connection establishing protocol.
	 * tcpfd = ...
	 */

	return (0);
}
