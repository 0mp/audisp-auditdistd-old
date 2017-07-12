#include <sys/socket.h>

#include <err.h>
#include <netdb.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#define ADIST_ADDR "192.168.56.102"
#define ADIST_PORT 7878
#define ADIST_WELCOME_MSG "ADIST00"

int
tcp_connect(void)
{
	struct sockaddr_in destaddr;
	int sockfd;
	int ret;
	struct hostent *desthost;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	desthost = gethostbyname(ADIST_ADDR);
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
main(void)
{
	SSL_CTX *sslctx;
	SSL *ssl;
	int tcpfd;
	int ret;

	SSL_library_init();

	sslctx = SSL_CTX_new(TLSv1_client_method());
	if (sslctx == NULL)
		err(1, "Failed to create a new SSL_CTX object");

	SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	ssl = SSL_new(sslctx);
	if (ssl == NULL)
		err(1, "Failed to create a new SSL context for a connection");

	tcpfd = tcp_connect();
	if (tcpfd == 0)
		err(1, "Failed to establish an underlying TCP connection");

	SSL_set_fd(ssl, tcpfd);

	ret = SSL_connect(ssl);
	if (ret != 1)
		err(1, "Failed to connect over SSL");

    SSL_write(ssl, ADIST_WELCOME_MSG, sizeof(ADIST_WELCOME_MSG));

	SSL_free(ssl);
	close(tcpfd);
	SSL_CTX_free(sslctx);

	return (0);
}
