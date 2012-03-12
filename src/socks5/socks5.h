#ifndef __SOCKS5__
#define __SOCKS5__

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

struct _socks5_t;

typedef struct _socks5_api_t {
	int (*socket)(struct _socks5_t *s5, int socket_family,
		int socket_type, int protocol);

	int (*connect)(struct _socks5_t *s5, int sockfd,
		const struct sockaddr *addr, socklen_t addrlen);
	
	int (*getaddrinfo)(struct _socks5_t *s5, const char *node,
		const char *service, const struct addrinfo *hints,
		struct addrinfo **res);

	void (*freeaddrinfo)(struct _socks5_t *s5, struct addrinfo *res);

	ssize_t (*send)(struct _socks5_t *s5, int sockfd, const void *buf,
		size_t len, int flags);
	
	ssize_t (*sendto)(struct _socks5_t *s5, int sockfd, const void *buf,
		size_t len, int flags, const struct sockaddr *dest_addr,
		socklen_t addrlen);
	
	ssize_t (*recv)(struct _socks5_t *s5, int sockfd, void *buf,
		size_t len, int flags);
	
	ssize_t (*recvfrom)(struct _socks5_t *s5, int sockfd, void *buf,
		size_t len, int flags, struct sockaddr *src_addr,
		socklen_t *addrlen);
	
	int (*close)(struct _socks5_t *s5, int fd);
} socks5_api_t;

typedef struct _socks5_t {
	// pointer to socket api implementation
	const socks5_api_t *api;
	// proxy server's hostname
	const char *server;
	// proxy server's port
	unsigned short port;
	// socket fd
	int fd;
	// our socks address type
	struct {
		// 1 = ipv4, 3 = hostname, 4 = ipv6
		int atyp;
		unsigned short port;
		union {
			struct in_addr ipv4;
			struct in6_addr ipv6;
			char hostname[256];
		} u;
	} addr;
	// 3rd party argument
	void *arg;
} socks5_t;

// initialize a new socks5 session
socks5_t *socks5_init(const socks5_api_t *api, void *arg);

// set the proxy server
void socks5_set_server(socks5_t *s5, const char *server, unsigned short port);

// connect to the proxy server & authorize
int socks5_connect_proxy_server(socks5_t *s5);

// initialize a connection to the internet
int socks5_proxy_ipv4(socks5_t *s5, const struct sockaddr_in *addr);
int socks5_proxy_ipv6(socks5_t *s5, const struct sockaddr_in6 *addr);
int socks5_proxy_hostname(socks5_t *s5, const char *hostname,
	unsigned short port);

void socks5_close(socks5_t *s5);
void socks5_free(socks5_t *s5);

#endif
