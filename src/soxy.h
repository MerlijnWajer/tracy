
typedef struct _proxy_t {
    // temporary map allocated in the child, used during connecting to
    // the proxy server.
    tracy_child_addr_t map;

    // the address of the proxy in use
    struct in_addr addr;
    unsigned short port;

    // temporary return value
    int return_code;
    int change_return_code;
} proxy_t;

typedef struct __attribute__((packed)) _soxy_ipv4_request_t {
    unsigned char ver;
    unsigned char cmd;
    unsigned char rsv;
    unsigned char atyp;
    struct in_addr addr;
    unsigned short port;
} soxy_ipv4_request_t;

typedef struct __attribute__((packed)) _soxy_ipv6_request_t {
    unsigned char ver;
    unsigned char cmd;
    unsigned char rsv;
    unsigned char atyp;
    struct in6_addr addr;
    unsigned short port;
} soxy_ipv6_request_t;

typedef struct __attribute__((packed)) _soxy_ipv4_reply_t {
    unsigned char ver;
    unsigned char rep;
    unsigned char rsv;
    unsigned char atyp;
    struct in_addr addr;
    unsigned short port;
} soxy_ipv4_reply_t;
