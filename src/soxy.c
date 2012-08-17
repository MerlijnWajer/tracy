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

long boe, ba;

static void get_proxy_server(struct sockaddr *addr, socklen_t *proxy_addr_len) {
    static int first = 0; static struct sockaddr _addr;
    if(first == 0) {
        memset(&_addr, 0, sizeof(_addr));

        struct sockaddr_in *addr4 = (struct sockaddr_in *) &_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = 0x0100007f;
        addr4->sin_port = htons(9050);
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
        return ll_add((struct tracy_ll *) e->child->custom, fd, proxy);
    }
}

#ifdef __i386__
static int soxy_hook_socketcall(struct tracy_event *e) {
    long nr;
    long read;
    unsigned long *args = malloc(sizeof(long) * 3);
    nr = e->args.a0;

    read = tracy_read_mem(e->child, (tracy_parent_addr_t) args,
            (tracy_child_addr_t) e->args.a1, sizeof(long) * 3);

    if (read != sizeof(long) * 3) {
        fprintf(stderr, "Reading socketcall arguments failed\n");
        _exit(1);
    }
    if (nr == SYS_SOCKET) {
        e->args.a0 = args[0];
        e->args.a1 = args[1];
        e->args.a2 = args[2];
        soxy_hook_socket(e);
    } else {
        e->args.a0 = args[0];
        e->args.a1 = args[1];
        e->args.a2 = args[2];
        soxy_hook_connect(e);
    }
    return 0;
}
#endif

static int soxy_connect(struct tracy_event *e,
        int sockfd, const struct sockaddr *addr,
        socklen_t addrlen) {
#ifdef __i386__
    ssize_t args_len;
    unsigned long *args;
    long ret;
    tracy_child_addr_t mem;

    if(tracy_mmap(e->child, &mem, NULL, 0x1000,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
            0) != 0) {
        fprintf(stderr, "soxy_connect: tracy_mmap failed\n");
        _exit(1);
    }

    args_len = sizeof(int) + sizeof(const struct sockaddr *) + sizeof(socklen_t);
    args = malloc(args_len);
    args[0] = sockfd;
    args[1] = (long)addr;
    args[2] = addrlen;

    if(tracy_write_mem(e->child, mem, args, args_len)
            != (ssize_t) args_len) {
        fprintf(stderr, "soxy_connect: tracy_write_mem failed\n");
        _exit(1);
    }

    e->args.a0 = SYS_CONNECT;
    e->args.a1 = (long)mem;
    ret = 0;

    if (tracy_inject_syscall(e->child, __NR_socketcall, &(e->args), &ret) || ret < 0) {
        fprintf(stderr, "soxy_connect: tracy_inject_syscall failed\n");
        _exit(1);
    }

    return ret;
    /* TODO: munmap */
#else
    long ret;

    e->args.a0 = sockfd;
    e->args.a1 = addr;
    e->args.a2 = addrlen;

    if (tracy_inject_syscall(e->child, __NR_connect, &(e->args), &ret) || ret < 0) {
        fprintf(stderr, "soxy_connect: tracy_inject_syscall failed\n");
        _exit(1);
    }

    return ret;
#endif
}

static int soxy_hook_socket(struct tracy_event *e) {
    proxy_t * proxy;
    if (!e->child->pre_syscall) {
        if(boe == AF_INET && ba == SOCK_STREAM) {
            fprintf(stderr, "We found a relevant fd\n");
            proxy = (proxy_t *) calloc(1, sizeof(proxy_t));
            if(proxy == NULL) {
                fprintf(stderr, "soxy_hook_socket: calloc failed\n");
                return -1;
            }

            proxy_set(e, e->args.return_code, proxy);
        }

    } else {
        boe = e->args.a0;
        ba = e->args.a1;
    }
    return TRACY_HOOK_CONTINUE;
}

static int soxy_set_blocking(struct tracy_event *e, int fd) {
    long flags, ret;
    struct tracy_sc_args fcntl_args = {fd, F_GETFL, 0,
        0, 0, 0, 0, 0, 0, 0};
    if (tracy_inject_syscall(e->child, __NR_fcntl, &fcntl_args, &flags)) {
        fprintf(stderr, "F_GETFL failed\n");
        return 0;
    }
    fprintf(stderr, "fcntl returns: %ld\n", flags);

    if ((flags & O_NONBLOCK) > 0) {
        fprintf(stderr, "Socket is nonblocking!\n");
        flags = (flags & ~O_NONBLOCK);

        struct tracy_sc_args fcntl_args = {fd, F_SETFL, flags,
            0, 0, 0, 0, 0, 0, 0};
        if (tracy_inject_syscall(e->child, __NR_fcntl, &fcntl_args, &ret)) {
            fprintf(stderr, "F_GETFL failed\n");
            return 0;
        }
        fprintf(stderr, "fcntl returns: %ld\n", ret);
    } else {
        fprintf(stderr, "Socket is blocking\n");
    }

    return flags;
}

static int soxy_set_nonblocking(struct tracy_event *e, int fd, int flags) {
    long ret;
    struct tracy_sc_args fcntl_args = {fd, F_SETFL, flags,
        0, 0, 0, 0, 0, 0, 0};
    if (tracy_inject_syscall(e->child, __NR_fcntl, &fcntl_args, &ret)) {
        fprintf(stderr, "F_GETFL failed\n");
        return 1;
    }
    fprintf(stderr, "fcntl returns: %ld\n", ret);
    return 0;
}

static int soxy_hook_connect(struct tracy_event *e) {
    long flags;
    int fd;
    long ret;

    ret = 0;

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

            flags = soxy_set_blocking(e, fd);

            // establish a connection to the proxy server.
            if(soxy_connect_proxy_server(e, e->args.a0) < 0) {
                return 0;
            }
            fprintf(stderr, "Soxy connect proxy server succeeded.\n");

            // we have now successfully "authed" to the proxy server, now it's
            // time to give the proxy server the information where to connect.
            if(soxy_connect_addr(e, e->args.a0, (struct sockaddr *) &addr)
                    < 0) {
                return 0;
            }

            fprintf(stderr, "Soxy connect addr succeeded.\n");
            if ((flags & O_NONBLOCK) > 0) {
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
            args.return_code = proxy->return_code;
#ifdef i686
            tracy_modify_syscall_regs(e->child, __NR_socketcall, &args);
#else
            tracy_modify_syscall_regs(e->child, __NR_connect, &args);
#endif
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
    if(tracy_write_mem(e->child, proxy->map, &proxy_addr, proxy_addr_len)
            != (ssize_t) proxy_addr_len) {
        perror("tracy_write_mem(proxy-sockaddr)");
        return -1;
    }

    // connect to the proxy server
    long ret = 0;
    ret = soxy_connect(e, fd, proxy->map, proxy_addr_len);
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
    if(tracy_inject_syscall(e->child, __NR_write, &args1, &ret) != 0 ||
            ret != 3) {
        perror("tracy_inject_syscall(write-send-auth-packet)");
        return -1;
    }

    // retrieve proxy server's response
    struct tracy_sc_args args2 = {fd, (long) proxy->map, 0x1000, 0, 0, 0, 0,
        0, 0, 0};
    if(tracy_inject_syscall(e->child, __NR_read, &args2, &ret) != 0 ||
            ret != 2) {
        perror("tracy_inject_syscall(recv-auth-response)");
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
        if(tracy_inject_syscall(e->child, __NR_write, &args, &ret) != 0 ||
                ret != sizeof(req)) {
            perror("tracy_inject_syscall(ipv4-connect-request)");
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
    if(tracy_inject_syscall(e->child, __NR_read, &args1, &ret) != 0 ||
            ret != sizeof(soxy_ipv4_reply_t)) {
        printf("ret = %ld\n", ret);
        perror("tracy_inject_syscall(read-ipv4-reply)");
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

#ifdef __i386__
    if(tracy_set_hook(tracy, "socketcall", &soxy_hook_socketcall)) {
        fprintf(stderr, "Error hooking socketcall(2)\n");
        return EXIT_FAILURE;
    }
#else
    if(tracy_set_hook(tracy, "socket", &soxy_hook_socket)) {
        fprintf(stderr, "Error hooking socket(2)\n");
        return EXIT_FAILURE;
    }

    if(tracy_set_hook(tracy, "connect", &soxy_hook_connect)) {
        fprintf(stderr, "Error hooking connect(2)\n");
        return EXIT_FAILURE;
    }
#endif

    if(tracy_set_hook(tracy, "close", &soxy_hook_close)) {
        fprintf(stderr, "Error hooking close(2)\n");
        return EXIT_FAILURE;
    }

    tracy_exec(tracy, ++argv);

    tracy_main(tracy);
    tracy_free(tracy);
    return 0;
}
