
typedef struct _socks5_request_ipv4_t {
	unsigned char ver;
	unsigned char cmd;
	unsigned char rsv;
	unsigned char atyp;
	unsigned long addr;
	unsigned short port;
} socks5_request_ipv4_t;

typedef struct _socks5_request_domain_t {
	unsigned char ver;
	unsigned char cmd;
	unsigned char rsv;
	unsigned char atyp;
	unsigned char len;
	unsigned char hostname[];
	// unsigned short port;
} socks5_request_domain_t;

typedef struct _socks5_reply_ipv4_t {
	unsigned char ver;
	unsigned char rep;
	unsigned char rsv;
	unsigned char atyp;
	unsigned long addr;
	unsigned short port;
} socks5_reply_ipv4_t;


