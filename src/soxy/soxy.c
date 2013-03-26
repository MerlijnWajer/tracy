#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <unistd.h>

#include "tracy.h"
#include "ll.h"

#include <sys/syscall.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <linux/net.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

#include "soxy.h"

#define tracee_perror(err, str) \
{ \
    long tmp = errno; \
    errno = err; \
    perror(str); \
    errno = tmp; \
}

#ifdef __i386__
#define HAVE_SOCKETCALL(x) \
    1
#endif
#ifdef __x86_64__
#define HAVE_SOCKETCALL(x) \
    (x == TRACY_ABI_X86)
#endif
#ifdef __arm__
#define HAVE_SOCKETCALL(x) \
    0
#endif


/* TODO: Store this somewhere in a safe manner */
long boe, ba;

static void get_proxy_server(struct sockaddr *addr, socklen_t *proxy_addr_len) {
    static int first = 0; static struct sockaddr _addr;
    if(first == 0) {
        memset(&_addr, 0, sizeof(_addr));

        struct sockaddr_in *addr4 = (struct sockaddr_in *) &_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = 0x0100007f;
        addr4->sin_port = htons(8888);
        first = 1;
    }

    memcpy(addr, &_addr, sizeof(struct sockaddr_in));
    *proxy_addr_len = sizeof(struct sockaddr_in);
}

static proxy_t *proxy_find(struct tracy_event *e, int fd) {
    struct tracy_ll_item *p = ll_find((struct tracy_ll *) e->child->custom, fd);
    return (p != NULL) ? (proxy_t *) p->data : NULL;
}

static int proxy_set(struct tracy_event *e, int fd, proxy_t *proxy) {
    if(proxy == NULL) {
        return ll_del((struct tracy_ll *) e->child->custom, fd);
    }
    else {
        printf("*** Setting proxy: %d\n", fd);
        return ll_add((struct tracy_ll *) e->child->custom, fd, proxy);
    }
}

static int soxy_hook_socketcall(struct tracy_event *e) {
    long nr;
    long read;
    uint32_t *args = malloc(sizeof(uint32_t) * 3);
    nr = (long)(int)e->args.a0;

    read = tracy_read_mem(e->child, (tracy_parent_addr_t) args,
            (tracy_child_addr_t) e->args.a1, sizeof(uint32_t) * 3);

    if (read != sizeof(uint32_t) * 3) {
        fprintf(stderr, "Reading socketcall arguments failed\n");
        _exit(1);
    }

    printf("Syscall: %ld", nr);
    printf(" args: %u, %x, %u\n", args[0], args[1], args[2]);

    if (nr == SYS_SOCKET) {
        e->args.a0 = args[0];
        e->args.a1 = args[1];
        e->args.a2 = args[2];
        return soxy_hook_socket(e);
    } else {
        e->args.a0 = args[0];
        e->args.a1 = args[1];
        e->args.a2 = args[2];
        return soxy_hook_connect(e);
    }
}
static int connect_socketcall(
        struct tracy_event *e,
        int sockfd, const struct sockaddr *addr,
        socklen_t addrlen) {
    ssize_t args_len;
    unsigned long *args;
    long ret;
    long socketcall_nr;
    tracy_child_addr_t mem;

    if(tracy_mmap(e->child, &mem, NULL, 0x1000,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
            0) != 0) {
        fprintf(stderr, "soxy_connect: tracy_mmap failed\n");
        _exit(1);
    }

    args_len = sizeof(int) + sizeof(const struct sockaddr *) + sizeof(socklen_t);
    args = malloc(args_len);
    if (HAVE_SOCKETCALL(e->abi)) {
        uint32_t *p = (uint32_t)args;
        p[0] = sockfd;
        p[1] = (long)addr;
        p[2] = addrlen;
        printf("Args: Sockfd: %d, Addr: %x, Addrlen: %d\n", p[0], p[1], p[2]);
    } else {
        args[0] = sockfd;
        args[1] = (long)addr;
        args[2] = addrlen;
        printf("Args: Sockfd: %ld, Addr: %lx, Addrlen: %ld\n", args[0], args[1], args[2]);
    }

    if(tracy_write_mem(e->child, mem, args, args_len)
            != (ssize_t) args_len) {
        fprintf(stderr, "soxy_connect: tracy_write_mem failed\n");
        _exit(1);
    }

    e->args.a0 = SYS_CONNECT;
    e->args.a1 = (long)(uint32_t)mem;
    printf("Arguments: %ld | %lx\n", e->args.a0, e->args.a1);
    ret = 0;

    socketcall_nr = get_syscall_number_abi("socketcall", e->abi);
    printf("socketcall_nr: %ld\n", socketcall_nr);
    long res = tracy_inject_syscall(e->child, socketcall_nr, &(e->args), &ret);
    printf("res: %ld\n", res);
    printf("ret: %ld\n", ret);
    if (res || ret < 0) {
        tracee_perror(-ret, "soxy_connect: socketcall, tracy_inject_syscall failed");
        _exit(1);
    }

    return ret;
}

static int soxy_connect(struct tracy_event *e,
        int sockfd, const struct sockaddr *addr,
        socklen_t addrlen, int socket_call) {
    if (socket_call) {
        return connect_socketcall(e, sockfd, addr, addrlen);
    } else {
        long ret = 0;

        e->args.a0 = sockfd;
        e->args.a1 = (long)addr;
        e->args.a2 = addrlen;

        if (tracy_inject_syscall(e->child,
                    get_syscall_number_abi("connect", TRACY_ABI_NATIVE),
                    &(e->args), &ret) || ret < 0) {
            tracee_perror(-ret, "soxy_connect: tracy_inject_syscall failed");
            _exit(1);
        }

        return ret;
    }
}

static int soxy_hook_socket(struct tracy_event *e) {
    proxy_t * proxy;

    if (e->child->pre_syscall) {
        /* FIXME */
        printf("Storing boe, ba\n");
        boe = e->args.a0;
        ba =  e->args.a1;

    } else {
        printf("boe: %ld; ba: %ld\n", boe, ba);
        if(boe == AF_INET && ba == SOCK_STREAM) {
            fprintf(stderr, "We found a relevant fd\n");
            proxy = (proxy_t *) calloc(1, sizeof(proxy_t));
            if(proxy == NULL) {
                fprintf(stderr, "soxy_hook_socket: calloc failed\n");
                return -1;
            }

            proxy_set(e, e->args.return_code, proxy);
        }

    }
    return TRACY_HOOK_CONTINUE;
}

/* This function will temporarily change a socket from being non-blocking to
 * blocking to ease the initial SOCKS 5 connection. */
static int soxy_set_blocking(struct tracy_event *e, int fd, long *flags) {
    long ret, fcntl_nr;
    long nonblocking;
    struct tracy_sc_args fcntl_args = {fd, F_GETFL, 0,
        0, 0, 0, 0, 0, 0, 0};

    fcntl_nr = get_syscall_number_abi("fcntl", e->abi);
    if (tracy_inject_syscall(e->child, fcntl_nr, &fcntl_args, flags)) {

        tracee_perror(-*flags, "soxy_set_blocking: F_GETFL failed");
        fprintf(stderr, "F_GETFL failed\n");
        return 0;
    }
    fprintf(stderr, "fcntl returns: %ld\n", *flags);

    nonblocking = (*flags & O_NONBLOCK) > 0;
    if (nonblocking) {
        fprintf(stderr, "Socket is nonblocking!\n");
        *flags = (*flags & ~O_NONBLOCK);

        struct tracy_sc_args fcntl_args = {fd, F_SETFL, *flags,
            0, 0, 0, 0, 0, 0, 0};
        if (tracy_inject_syscall(e->child, fcntl_nr, &fcntl_args, &ret)) {
            tracee_perror(-ret, "soxy_set_blocking: F_GETFL failed");
            return 0;
        }
        fprintf(stderr, "fcntl returns: %ld\n", ret);
    } else {
        fprintf(stderr, "Socket is blocking\n");
    }

    return nonblocking;
}

/* This function will change a socket from blocking to non-blocking to
 * undo the effect of ``soxy_set_blocking''. */
static int soxy_set_nonblocking(struct tracy_event *e, int fd, int flags) {
    long ret, fcntl_nr;
    struct tracy_sc_args fcntl_args = {fd, F_SETFL, flags,
        0, 0, 0, 0, 0, 0, 0};
    fcntl_nr = get_syscall_number_abi("fcntl", e->abi);
    if (tracy_inject_syscall(e->child, fcntl_nr, &fcntl_args, &ret)) {
        tracee_perror(-ret, "soxy_set_blocking: F_SETFL failed");
        return 1;
    }
    fprintf(stderr, "fcntl returns: %ld\n", ret);
    return 0;
}

static int soxy_hook_connect(struct tracy_event *e) {
    long flags;
    long nonblocking;
    int fd;

    if(e->child->pre_syscall) {
        struct sockaddr_in addr;

        if(
            // check if the size of the address object is correct
            (unsigned long) e->args.a2 == sizeof(struct sockaddr_in) &&
            //(unsigned long) e->args.a2 >= sizeof(struct sockaddr_in) &&

            // if proxy_find() returns NULL, then we are not interested in
            // this fd (could be udp, etc.)
            proxy_find(e, e->args.a0) != NULL &&

            // read the sockaddr from the child into `addr'
            tracy_read_mem(e->child, &addr, (tracy_parent_addr_t) e->args.a1,
                e->args.a2) == e->args.a2
        ) {
            fd = e->args.a0;

            proxy_t *proxy = proxy_find(e, e->args.a0);
            proxy->change_return_code = 1;
            // by default we return failure
            proxy->return_code = -1;

            nonblocking = soxy_set_blocking(e, fd, &flags);

            // establish a connection to the proxy server.
            if(soxy_connect_proxy_server(e, e->args.a0) < 0) {
                return 0;
            }
            fprintf(stderr, "Soxy connect proxy server succeeded.\n");

            // we have now successfully "authed" to the proxy server, now it's
            // time to give the proxy server the information where to connect.
            if(soxy_connect_addr(e, fd, (struct sockaddr *) &addr) < 0) {
                return 0;
            }

            fprintf(stderr, "Soxy connect addr succeeded.\n");
            if (nonblocking) {
                flags = (flags | O_NONBLOCK);
                soxy_set_nonblocking(e, fd, flags);
            }

            if(tracy_deny_syscall(e->child)) {
                fprintf(stderr, "Error denying connect(2) syscall.\n");
                return 0;
            }

            // return success.
            proxy->return_code = 0;
        }
    }
    else {
        struct tracy_sc_args args; proxy_t *proxy;

        proxy = proxy_find(e, e->args.a0);
        if(proxy != NULL && proxy->change_return_code != 0) {
            // Set arguments
            memcpy(&args, &e->args, sizeof(args));
            args.return_code = (int32_t) proxy->return_code;
            if (HAVE_SOCKETCALL(e->abi)) {
                {
                long socketcall_nr = get_syscall_number_abi("socketcall", e->abi);
                if (tracy_modify_syscall_regs(e->child, socketcall_nr, &args)) {
                    fprintf(stderr, "Tracy_modify_syscall_regs failed\n");
                }
                }
            } else {
                {
                long connect_nr = get_syscall_number_abi("connect", e->abi);
                if(tracy_modify_syscall_regs(e->child, connect_nr, &args)) {
                    fprintf(stderr, "Tracy_modify_syscall_regs failed\n");
                }
                }
            }
        }
    }
    return 0;
}

static int soxy_hook_close(struct tracy_event *e) {
    long ret;
    proxy_t * proxy;

    if(e->child->pre_syscall) {
        proxy = proxy_find(e, e->args.a0);
        if(proxy != NULL) {
            if(proxy->map != NULL) {
                /* assume it doesn't fail. */
                tracy_munmap(e->child, &ret, proxy->map, 0x1000);
                proxy->map = NULL;
            }
            free(proxy);
            proxy_set(e, e->args.a0, NULL);
        }
    }
    return 0;
}

static void soxy_child_create(struct tracy_child *child) {
    child->custom = ll_init();
}

static int soxy_connect_proxy_server(struct tracy_event *e, int fd)
{
    struct sockaddr proxy_addr;
    socklen_t proxy_addr_len;
    get_proxy_server(&proxy_addr, &proxy_addr_len);

    proxy_t *proxy = proxy_find(e, fd);

    // allocate memory in the child
    if(tracy_mmap(e->child, &proxy->map, NULL, 0x1000,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
            0) != 0) {
        perror("tracy_mmap(child-memory)");
        return -1;
    }

    // write the proxy server's sockaddr
    long r;
    r = tracy_write_mem(e->child, proxy->map, &proxy_addr, proxy_addr_len);
    if(r != (ssize_t) proxy_addr_len) {
        perror("tracy_write_mem(proxy-sockaddr)");
        return -1;
    }

    // connect to the proxy server
    long ret = 0;
    ret = soxy_connect(e, fd, proxy->map, proxy_addr_len, HAVE_SOCKETCALL(e->abi));
    if (ret < 0) {
        fprintf(stderr, "connect-proxy-server: ret = %ld\n", ret);
        return -1;
    }
    // request auth method (we only support no-auth)
    if(tracy_write_mem(e->child, proxy->map, "\x05\x01\x00", 3) != 3) {
        perror("tracy_write_mem(request-auth-packet)");
        return -1;
    }

    struct tracy_sc_args args1 = {fd, (long) proxy->map, 3, 0, 0, 0, 0, 0,
        0, 0};

    long write_nr = get_syscall_number_abi("write", e->abi);
    if(tracy_inject_syscall(e->child, write_nr, &args1, &ret) != 0 ||
            ret != 3) {
        tracee_perror(-ret, "tracy_inject_syscall(write-send-auth-packet)");
        return -1;
    }

    // retrieve proxy server's response
    struct tracy_sc_args args2 = {fd, (long) proxy->map, 0x1000, 0, 0, 0, 0,
        0, 0, 0};
    long read_nr = get_syscall_number_abi("read", e->abi);
    if(tracy_inject_syscall(e->child, read_nr, &args2, &ret) != 0 ||
            ret != 2) {
        tracee_perror(-ret, "tracy_inject_syscall(recv-auth-response)");
        return -1;
    }

    char buf[2];
    if(tracy_read_mem(e->child, buf, proxy->map, 2) != 2) {
        perror("tracy_read_mem(recv-auth-response)");
        return -1;
    }

    // check the auth response
    if(buf[0] != 0x05 || buf[1] != 0x00) {
        fprintf(stderr, "Server doesn't support no-auth\n");
        return -1;
    }
    return 0;
}

static int soxy_connect_addr(struct tracy_event *e, int fd,
    struct sockaddr *addr)
{
    proxy_t *proxy = proxy_find(e, fd);
    if(proxy == NULL) {
        fprintf(stderr, "no proxy_t?\n");
        return -1;
    }

    long ret;

    // ipv4 address?
    if(((struct sockaddr_in *) addr)->sin_family == AF_INET) {

        // construct our ipv4-connection request packet
        soxy_ipv4_request_t req = {
            0x05, 0x01, 0x00, 0x01,
            ((struct sockaddr_in *) addr)->sin_addr,
            ((struct sockaddr_in *) addr)->sin_port,
        };

        // write our packet to the child
        if(tracy_write_mem(e->child, proxy->map, &req, sizeof(req))
                != sizeof(req)) {
            perror("tracy_write_mem(ipv4-connect-request)");
            return -1;
        }

        // send the packet over the socket
        struct tracy_sc_args args = {fd, (long) proxy->map, sizeof(req), 0,
            0, 0, 0, 0, 0, 0};
        long write_nr = get_syscall_number_abi("write", e->abi);
        if(tracy_inject_syscall(e->child, write_nr, &args, &ret) != 0 ||
                ret != sizeof(req)) {
            tracee_perror(-ret, "tracy_inject_syscall(ipv4-connect-request)");
            return -1;
        }
    }
    else {
        fprintf(stderr, "Invalid address type!\n");
        exit(0);
    }

    // receive the response from the server
    struct tracy_sc_args args1 = {fd, (long) proxy->map, 0x1000, 0, 0, 0, 0,
        0, 0, 0};
    long read_nr = get_syscall_number_abi("read", e->abi);
    if(tracy_inject_syscall(e->child, read_nr, &args1, &ret) != 0 ||
            ret != sizeof(soxy_ipv4_reply_t)) {
        printf("ret = %ld\n", ret);
        tracee_perror(-ret, "tracy_inject_syscall(read-ipv4-reply)");
        return -1;
    }

    soxy_ipv4_reply_t *reply = malloc(sizeof(soxy_ipv4_reply_t));
    if(tracy_read_mem(e->child, reply, proxy->map, sizeof(soxy_ipv4_reply_t))
            != sizeof(soxy_ipv4_reply_t)) {
        perror("tracy_read_mem(read-ipv4-reply)");
        return -1;
    }

    if(reply->ver != 0x05 || reply->rep != 0x00 || reply->rsv != 0x00 ||
            reply->atyp != 0x01) {
        fprintf(stderr, "Received an error!\n");
        return -1;
    }

    proxy->addr = reply->addr;
    proxy->port = reply->port;
    free(reply);
    return 0;
}

int main(int argc, char *argv[]) {
    struct tracy *tracy = tracy_init(TRACY_TRACE_CHILDREN);
    (void)argc;

    tracy->se.child_create = &soxy_child_create;

#ifdef __x86_64__
    if(tracy_set_hook(tracy, "socketcall", TRACY_ABI_X86,
                &soxy_hook_socketcall)) {
        fprintf(stderr, "Error hooking socketcall(2)\n");
        return EXIT_FAILURE;
    }
#endif
#ifdef __i386__
    if(tracy_set_hook(tracy, "socketcall", TRACY_ABI_NATIVE,
                &soxy_hook_socketcall)) {
        fprintf(stderr, "Error hooking socketcall(2)\n");
        return EXIT_FAILURE;
    }
#else
    if(tracy_set_hook(tracy, "socket", TRACY_ABI_NATIVE,
                &soxy_hook_socket)) {
        fprintf(stderr, "Error hooking socket(2)\n");
        return EXIT_FAILURE;
    }

    if(tracy_set_hook(tracy, "connect", TRACY_ABI_NATIVE,
                &soxy_hook_connect)) {
        fprintf(stderr, "Error hooking connect(2)\n");
        return EXIT_FAILURE;
    }
#endif

    if(tracy_set_hook(tracy, "close", TRACY_ABI_NATIVE,
                &soxy_hook_close)) {
        fprintf(stderr, "Error hooking close(2)\n");
        return EXIT_FAILURE;
    }

    tracy_exec(tracy, ++argv);

    tracy_main(tracy);
    tracy_free(tracy);
    return 0;
}
