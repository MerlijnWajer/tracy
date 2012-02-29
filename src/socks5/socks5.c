#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "socks5.h"
#include "socks5_internal.h"

//
// Default Callback Handlers
//

static int handler_socket(int socket_family, int socket_type, int protocol,
	socks5_t *s5)
{
	(void)s5;
	return socket(socket_family, socket_type, protocol);
}

static int handler_connect(int sockfd, const struct sockaddr *addr,
	socklen_t addrlen, socks5_t *s5)
{
	(void)s5;
	return connect(sockfd, addr, addrlen);
}

static ssize_t handler_send(int sockfd, const void *buf, size_t len,
	int flags, socks5_t *s5)
{
	(void)s5;
	return send(sockfd, buf, len, flags);
}

static int handler_getaddrinfo(const char *node, const char *service,
	const struct addrinfo *hints, struct addrinfo **res, socks5_t *s5)
{
	(void)s5;
	return getaddrinfo(node, service, hints, res);
}

static void handler_freeaddrinfo(struct addrinfo *res, socks5_t *s5)
{
	(void)s5;
	return freeaddrinfo(res);
}

static ssize_t handler_sendto(int sockfd, const void *buf, size_t len,
	int flags, const struct sockaddr *dest_addr, socklen_t addrlen,
	socks5_t *s5)
{
	(void)s5;
	return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

static ssize_t handler_recv(int sockfd, void *buf, size_t len,
	int flags, socks5_t *s5)
{
	(void)s5;
	return recv(sockfd, buf, len, flags);
}

static ssize_t handler_recvfrom(int sockfd, void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen, socks5_t *s5)
{
	(void)s5;
	return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

static socks5_api_t default_handler = {
	&handler_socket,
	&handler_connect,
	&handler_getaddrinfo,
	&handler_freeaddrinfo,
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
		s5->arg = arg;
	}
	return s5;
}

void socks5_set_proxy(socks5_t *s5, const char *server, unsigned short port)
{
	s5->server = strdup(server);
	s5->port = port;
}

int socks5_connect_proxy_server(socks5_t *s5)
{
	int res, fd = -1; struct addrinfo *addr = NULL, *base = NULL;
	char port_number[16], buf[128];
	static const struct addrinfo hint = {AF_UNSPEC, SOCK_STREAM};

	// someone decided itoa() is not ANSI C... 
	sprintf(port_number, "%d", s5->port);
	// resolve the address of the proxy server
	res = CB(getaddrinfo, s5->server, port_number, &hint, &addr);
	if(res < 0) goto cleanup;

	// try to connect to the server
	for (base = addr; addr != NULL; addr = addr->ai_next) {
		// try to get a socket with this socket type
		fd = CB(socket, addr->ai_family, addr->ai_socktype,
			addr->ai_protocol);
		if(fd < 0) continue;

		// try to connect to the proxy server
		res = CB(connect, fd, addr->ai_addr, addr->ai_addrlen);
		if(res < 0) goto cleanup;

		// got our socket!
		break;
	}

	// free the addrinfo structures
	CB(freeaddrinfo, base);

	// error getting a socket?
	if(fd < 0) {
		res = -1;
		goto cleanup;
	}

	// request auth method (supports no-auth and user/pass)
	res = CB(send, fd, "\x05\x02\x00\x02", 4, 0);
	if(res < 0) goto cleanup;

	// get proxy server response
	res = CB(recv, fd, buf, sizeof(buf), 0);
	if(res < 0) goto cleanup;

	// atm we only support "no auth"
	if(res != 2 || buf[0] != 0x05 || buf[0] != 0x00) {
		res = -1; goto cleanup;
	}

	// proxy server connection is successful.
	s5->fd = fd;
	return 0;

cleanup:
	if(fd != -1) close(fd);
	return res;
}

static int socks5_proxy_handle_reply(socks5_t *s5, socks5_reply_ipv4_t *reply)
{
	// ...
	return -1;
}

int socks5_proxy_ipv4(socks5_t *s5, const sockaddr_in *addr)
{
	socks5_request_ipv4_t request = {
		0x05,					// version
		0x01,					// command (connect)
		0x00,					// reserved
		0x01,					// atyp (ipv4)
		addr->sin_addr.s_addr,	// ipv4 address
		addr->sin_port,			// port
	};
	int res = CB(send, s5->fd, &request, sizeof(request), 0);
	if(res < 0) return res;

	char buf[128];
	res = CB(recv, s5->fd, buf, sizeof(buf), 0);
	if(res < sizeof(socks5_reply_ipv4_t)) return -1;

	socks5_reply_ipv4_t *reply = (socks5_reply_ipv4_t *) buf;
	return socks5_proxy_handle_reply(s5, reply);
}

int socks5_proxy_ipv6(socks5_t *s5, const sockaddr *addr)
{
	// ...
	return -1;
}

