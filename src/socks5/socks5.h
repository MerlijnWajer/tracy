#ifndef __SOCKS5__
#define __SOCKS5__

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

struct _socks5_t;

typedef struct _socks5_api_t {
	int (*socket)(int socket_family, int socket_type, int protocol,
		struct _socks5_t *s5);

	int (*connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen,
		struct _socks5_t *s5);
	
	int (*getaddrinfo)(const char *node, const char *service, const struct
		addrinfo *hints, struct addrinfo **res, struct _socks5_t *s5);

	void (*freeaddrinfo)(struct addrinfo *res, struct _socks5_t *s5);

	ssize_t (*send)(int sockfd, const void *buf, size_t len, int flags,
		struct _socks5_t *s5);
	
	ssize_t (*sendto)(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen,
		struct _socks5_t *s5);
	
	ssize_t (*recv)(int sockfd, void *buf, size_t len, int flags,
		struct _socks5_t *s5);
	
	ssize_t (*recvfrom)(int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen, struct _socks5_t *s5);
} socks5_api_t;

typedef struct _socks5_t {
	const socks5_api_t *api;
	const char *server;
	int port;
	void *arg;
	int fd;
} socks5_t;

// initialize a new socks5 session
socks5_t *socks5_init(const socks5_api_t *api, void *arg);

// connect to the proxy server & authorize
int socks5_connect_proxy_server(socks5_t *s5);

int socks5_connect_ipv4(socks5_t *s5, const struct sockaddr_in *addr);

#define CB(fn, ...) s5->api->fn(__VA_ARGS__, s5)

#endif
