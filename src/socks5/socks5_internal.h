
//
// SOCKS5 Request Headers
//

#define SOCKS5_REQUEST_MIN_LENGTH sizeof(socks5_request_ipv4_t)
#define SOCKS5_REQUEST_MAX_LENGTH sizeof(socks5_request_hostname_t)

typedef struct _socks5_request_bare_t {
	unsigned char ver;
	unsigned char cmd;
	unsigned char rsv;
	unsigned char atyp;
} socks5_request_bare_t;

typedef struct _socks5_request_ipv4_t {
	socks5_request_bare_t bare;
	struct in_addr addr;
	unsigned short port;
} socks5_request_ipv4_t;

typedef struct _socks5_request_ipv6_t {
	socks5_request_bare_t bare;
	struct in6_addr addr;
	unsigned short port;
} socks5_request_ipv6_t;

typedef struct _socks5_request_hostname_t {
	socks5_request_bare_t bare;
	unsigned char len;
	unsigned char hostname[255]; // maximal length of a hostname
	unsigned short _port; // offset depends on length of `hostname'
} socks5_request_hostname_t;

//
// SOCKS5 Reply Headers
//

#define SOCKS5_REPLY_MIN_LENGTH sizeof(socks5_reply_ipv4_t)
#define SOCKS5_REPLY_MAX_LENGTH sizeof(socks5_reply_hostname_t)

typedef struct _socks5_reply_bare_t {
	unsigned char ver;
	unsigned char rep;
	unsigned char rsv;
	unsigned char atyp;
} socks5_reply_bare_t;

typedef struct __attribute__((packed)) _socks5_reply_ipv4_t {
	socks5_reply_bare_t bare;
	struct in_addr addr;
	unsigned short port;
} socks5_reply_ipv4_t;

typedef struct __attribute__((packed)) _socks5_reply_ipv6_t {
	socks5_reply_bare_t bare;
	struct in6_addr addr;
	unsigned short port;
} socks5_reply_ipv6_t;

typedef struct _socks5_reply_hostname_t {
	socks5_reply_bare_t bare;
	unsigned char len;
	unsigned char hostname[255];
	unsigned short _port; // do not use directly (assuming len != 255)
} socks5_reply_hostname_t;

#ifndef MIN
inline int MIN(int a, int b) {
	return (a < b) ? a : b;
}
#endif

