#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "socks5.h"

//
// Default Callback Handlers
//

static int handler_connect(int sockfd, const struct sockaddr *addr,
	socklen_t addrlen, socks5_t *s5)
{
	return conncet(sockfd, addr, addrlen);
}

static ssize_t handler_send(int sockfd, const void *buf, size_t len,
	int flags, socks5_t *s5)
{
	return send(sockfd, buf, len, flags);
}

static ssize_t handler_sendto(int sockfd, const void *buf, size_t len,
	int flags, const struct sockaddr *dest_addr, socklen_t addrlen,
	socks5_t *s5)
{
	return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

static ssize_t handler_recv(int sockfd, void *buf, size_t len,
	int flags, socks5_t *s5)
{
	return recv(sockfd, buf, len, flags, 
}

static ssize_t handler_recvfrom(int sockfd, void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen, socks5_t *s5)
{
	return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

static socks5_api_t default_handler = {
	&handler_connect,
	&handler_send,
	&handler_sendto,
	&handler_recv,
	&handler_recvfrom,
};

socks5_t *socks5_init(const socks5_api_t *api, void *arg)
{
	socks5_t *s5 = (socks5_t *) calloc(1, sizeof(socks5_t));
	if(s5 != NULL) {
		s5->api = (api != NULL) ? api : &default_handler;
	}
	return s5;
}
