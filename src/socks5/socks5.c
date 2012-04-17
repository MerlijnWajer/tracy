#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "socks5.h"
#include "socks5_internal.h"

//
// Default Callback Handlers
//

static int handler_socket(socks5_t *s5, int socket_family, int socket_type,
	int protocol)
{
	(void)s5;
	return socket(socket_family, socket_type, protocol);
}

static int handler_connect(socks5_t *s5, int sockfd,
	const struct sockaddr *addr, socklen_t addrlen)
{
	(void)s5;
	return connect(sockfd, addr, addrlen);
}

static ssize_t handler_send(socks5_t *s5, int sockfd, const void *buf,
	size_t len, int flags)
{
	(void)s5;
	return send(sockfd, buf, len, flags);
}

static ssize_t handler_sendto(socks5_t *s5, int sockfd, const void *buf,
	size_t len, int flags, const struct sockaddr *dest_addr,
	socklen_t addrlen)
{
	(void)s5;
	return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

static ssize_t handler_recv(socks5_t *s5, int sockfd, void *buf, size_t len,
	int flags)
{
	(void)s5;
	return recv(sockfd, buf, len, flags);
}

static ssize_t handler_recvfrom(socks5_t *s5, int sockfd, void *buf,
	size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	(void)s5;
	return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

static int handler_close(socks5_t *s5, int fd)
{
	(void)s5;
	return close(fd);
}

static socks5_api_t default_handler = {
	&handler_socket,
	&handler_connect,
	&handler_send,
	&handler_sendto,
	&handler_recv,
	&handler_recvfrom,
	&handler_close,
};

//
// SOCKS5 Implementation (RFC 1922)
//

socks5_t *socks5_init(const socks5_api_t *api, void *arg)
{
	socks5_t *s5 = (socks5_t *) calloc(1, sizeof(socks5_t));
	if(s5 != NULL) {
		// use default api, if none were given
		s5->api = (api != NULL) ? api : &default_handler;
		s5->arg = arg;
	}
	return s5;
}

void socks5_set_server(socks5_t *s5, const char *server, unsigned short port)
{
	s5->server = strdup(server);
	s5->port = port;
}

int socks5_connect_proxy_server(socks5_t *s5)
{
	int res, fd = -1; struct addrinfo *addr = NULL, *base = NULL;
	char port_number[16], buf[128];
	static const struct addrinfo hint = {
		AI_NUMERICSERV, AF_UNSPEC, SOCK_STREAM, 0, 0, 0, 0, 0
	};

	// someone decided itoa() is not ANSI C... 
	sprintf(port_number, "%d", s5->port);
	// resolve the address of the proxy server
	res = getaddrinfo(s5->server, port_number, &hint, &addr);
	if(res < 0) goto cleanup;

	// try to connect to the server
	for (base = addr; addr != NULL; addr = addr->ai_next) {
		// try to get a socket with this socket type
		fd = s5->api->socket(s5, addr->ai_family, addr->ai_socktype,
			addr->ai_protocol);
		if(fd < 0) continue;

		// try to connect to the proxy server
		res = s5->api->connect(s5, fd, addr->ai_addr,
			addr->ai_addrlen);
		if(res < 0) goto cleanup;

		// got our socket!
		break;
	}

	// free the addrinfo structures
	freeaddrinfo(base);

	// error getting a socket?
	if(fd < 0) {
		res = -1;
		goto cleanup;
	}

	// request auth method (we only support no-auth)
	res = s5->api->send(s5, fd, "\x05\x01\x00", 3, 0);
	if(res != 3) {
		res = -1;
		goto cleanup;
	}

	// get proxy server response
	res = s5->api->recv(s5, fd, buf, sizeof(buf), 0);
	if(res < 0) goto cleanup;

	// atm we only support "no auth"
	if(res != 2 || buf[0] != 0x05 || buf[1] != 0x00) {
		res = -1; goto cleanup;
	}

	// proxy server connection is successful.
	s5->fd = fd;
	return 0;

cleanup:
	if(fd != -1) s5->api->close(s5, fd);
	return res;
}

static int socks5_proxy_handle_reply(socks5_t *s5)
{
	// 256 is max length for `hostname' and 2 for the port
	char buf[SOCKS5_REPLY_MAX_LENGTH];
	int res = s5->api->recv(s5, s5->fd, buf, sizeof(buf), 0);
	if((unsigned)res < SOCKS5_REPLY_MIN_LENGTH) return -1;
	socks5_reply_bare_t *bare = (socks5_reply_bare_t *) buf;
	// proxy server returned success
	if(bare->rep == 0) {
		// parse the server's address
		s5->addr.atyp = bare->atyp;
		switch (bare->atyp) {
		case 1: {
			socks5_reply_ipv4_t *ipv4 = \
				(socks5_reply_ipv4_t *) bare;
			s5->addr.u.ipv4 = ipv4->addr;
			s5->addr.port = ipv4->port;
			break;
		}
		case 3: {
			socks5_reply_hostname_t *host = \
				(socks5_reply_hostname_t *) bare;
			// yes, this is safe, of course. (len is max 255, our
			// hostname is 256, which includes null-byte.)
			strncpy(s5->addr.u.hostname, \
				(const char *) host->hostname, host->len + 1);
			s5->addr.port = \
				*(unsigned short *) &host->hostname[host->len];
			break;
		}
		case 4: {
			socks5_reply_ipv6_t *ipv6 = \
				(socks5_reply_ipv6_t *) bare;
			memcpy(&s5->addr.u.ipv6, &ipv6->addr, \
				sizeof(ipv6->addr));
			s5->addr.port = ipv6->port;
			break;
		}}		
		return 0;
	}
	return -1;
}

int socks5_proxy_ipv4(socks5_t *s5, const struct sockaddr_in *addr)
{
	socks5_request_ipv4_t request = {
		// version, command (connect), reserved, atyp (ipv4)
		{0x05, 0x01, 0x00, 0x01},
		addr->sin_addr,				// ipv4 address
		addr->sin_port,				// port
	};
	int res = s5->api->send(s5, s5->fd, &request, sizeof(request), 0);
	if(res != sizeof(request)) return -1;
	return socks5_proxy_handle_reply(s5);
}

int socks5_proxy_ipv6(socks5_t *s5, const struct sockaddr_in6 *addr)
{
	socks5_request_ipv6_t request = {
		// version, command (connect), reserved, atyp (ipv6)
		{0x05, 0x01, 0x00, 0x04},
		addr->sin6_addr,			// ipv6 address
		addr->sin6_port,			// port
	};
	int res = s5->api->send(s5, s5->fd, &request, sizeof(request), 0);
	if(res != sizeof(request)) return -1;
	return socks5_proxy_handle_reply(s5);
}

int socks5_proxy_hostname(socks5_t *s5, const char *hostname,
	unsigned short port)
{
	socks5_request_hostname_t request = {
		// version, command (connect), reserved, atyp (hostname)
		{0x05, 0x01, 0x00, 0x03},
		// dummy values for len, hostname, port
		0, "", 0
	};

	int len = strlen(hostname);
	// hostname cannot be larger than our maximum defined length
	if((unsigned) len > sizeof(request.hostname)) return -1;

	request.len = (unsigned char) len;
	memcpy(request.hostname, hostname, len);

	// `hostname' is followed directly by `port'
	*(unsigned short *) &request.hostname[request.len] = htons(port);
	
	// calculate size of the entire packet
	len += sizeof(socks5_request_bare_t) + sizeof(request.len) + \
		sizeof(request._port);
	int res = s5->api->send(s5, s5->fd, &request, len, 0);
	if(res != len) return -1;
	return socks5_proxy_handle_reply(s5);
}

void socks5_close(socks5_t *s5)
{
	if(s5->fd != -1) {
		close(s5->fd);
		s5->fd = -1;
	}
}

void socks5_free(socks5_t *s5)
{
	socks5_close(s5);
	free(s5);
}

