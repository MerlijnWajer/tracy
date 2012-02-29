#ifndef __SOCKS5__
#define __SOCKS5__

struct _socks5_t;

typedef struct _socks5_api_t {
	int (*connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen,
		struct _socks5_t *s5);
	
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
} socks5_t;

#endif
