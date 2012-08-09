/*
    This file is part of Tracy.

    Tracy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tracy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tracy.  If not, see <http://www.gnu.org/licenses/>.
*/
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

// resolves the address of the proxy server into `addr'
static void get_proxy_server(struct sockaddr *addr, socklen_t *proxy_addr_len)
{
    static int first = 0; static struct sockaddr _addr;
    if(first == 0) {
        memset(&_addr, 0, sizeof(_addr));

        struct sockaddr_in *addr4 = (struct sockaddr_in *) &_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = 0x0100007f;
        addr4->sin_port = htons(2222);
        first = 1;
    }

    memcpy(addr, &_addr, sizeof(struct sockaddr_in));
    *proxy_addr_len = sizeof(struct sockaddr_in);
}

static proxy_t *proxy_find(struct tracy_event *e, int fd)
{
    struct tracy_ll_item *p = ll_find((struct tracy_ll *) e->child->custom, fd);

    return (p != NULL) ? (proxy_t *) p->data : NULL;
}

static int proxy_set(struct tracy_event *e, int fd, proxy_t *proxy)
{
    if(proxy == NULL) {
        return ll_del((struct tracy_ll *) e->child->custom, fd);
    }
    else {
        return ll_add((struct tracy_ll *) e->child->custom, fd, proxy);
    }
}

static void soxy_child_create(struct tracy_child *child)
{
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
    struct tracy_sc_args args = {fd, (long) proxy->map, proxy_addr_len, 0,
        0, 0, 0, 0, 0, 0};
    
    if (tracy_inject_syscall(e->child, __NR_connect, &args, &ret) != 0 || ret < 0) {
        fprintf(stderr, "connect-proxy-server: ret = %ld\n", ret);
        perror("tracy_inject_syscall(connect-proxy-server)");
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
#ifdef _SOXY_IPV6_
    // ipv6 address?
    else if(((struct sockaddr_in6 *) addr)->sin6_family == AF_INET6) {

        // construct our ipv6-connection request packet
        soxy_ipv6_request_t req = {
            0x05, 0x01, 0x00, 0x04,
            ((struct sockaddr_in6 *) addr)->sin6_addr,
            ((struct sockaddr_in6 *) addr)->sin6_port,
        };

        // write our packet to the child
        if(tracy_write_mem(e->child, proxy->map, &req, sizeof(req))
                != sizeof(req)) {
            perror("tracy_write_mem(ipv6-connect-request)");
            return -1;
        }

        // send the packet over the socket
        struct tracy_sc_args args = {fd, (long) proxy->map, sizeof(req), 0,
            0, 0, 0, 0, 0, 0};
        if(tracy_inject_syscall(e->child, __NR_write, &args, &ret) != 0 ||
                ret != sizeof(req)) {
            perror("tracy_inject_syscall(ipv6-connect-request)");
            return -1;
        }
    }
#endif
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

struct in_addr udp_addr;
unsigned short udp_port;

/*
static int soxy_setup_udp()
{
    // check if the udp session has been setup already
    if(udp_addr.s_addr != 0 && udp_port != 0) {
        return 0;
    }

    struct sockaddr_in proxy_addr; socklen_t proxy_addr_len;
    get_proxy_server((struct sockaddr *) &proxy_addr, &proxy_addr_len);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) {
        perror("socket(socks5-udp-session)");
        return -1;
    }

    if(connect(s, &proxy_addr, proxy_addr_len) < 0) {
        perror("connect(socks5-udp-session)");
        goto cleanup;
    }

    // auth to the server, no encryption.
    if(send(s, "\x05\x01\x00", 3, 0) != 3) {
        perror("send(socks5-udp-session-auth)");
        goto cleanup;
    }

    char buf[2];
    if(recv(s, buf, sizeof(buf), 0) != sizeof(buf)) {
        perror("recv(socks5-udp-session-auth-response)");
        goto cleanup;
    }

    // success?
    if(buf[0] != 0x05 || buf[1] != 0x00) {
        fprintf(stderr, "Error authorizating to socks5 server.\n");
        goto cleanup;
    }

    // send an UDP Associate request, with an empty ip address & port.
    if(send(s, "\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0) != 10) {
        perror("send(socks5-udp-session-request)");
        goto cleanup;
    }

    soxy_ipv4_reply_t reply;
    if(recv(s, &reply, sizeof(reply), 0) != sizeof(reply)) {
        perror("send(socks5-udp-session-reply)");
        goto cleanup;
    }

    // was the UDP Associate request successful?
    if(reply.ver != 0x05 || reply.rep != 0x00 || reply.rsv != 0x00 ||
            reply.atyp != 0x01) {
        fprintf(stderr,
            "Error setting up an UDP session with the socks5 server.\n");
        goto cleanup;
    }

    udp_addr = reply.addr;
    udp_port = reply.port;
    return 0;

cleanup:
    close(s);
    return -1;
}
*/

static int soxy_hook_socket(struct tracy_event *e)
{
    if(e->child->pre_syscall == 0) {

#ifdef _SOXY_IPV6_
        if((e->args.a0 == AF_INET || e->args.a0 == AF_INET6) &&
                e->args.a1 == SOCK_STREAM) {
#else
        if(boe  == AF_INET && ba == SOCK_STREAM) {
        //if(e->args.a0 == AF_INET && e->args.a1 == SOCK_STREAM) {
#endif

            // store data about this fd (ie, it's memory map) in a linked list
            proxy_t *proxy = (proxy_t *) calloc(1, sizeof(proxy_t));
            if(proxy == NULL) {
                perror("calloc()");
                return -1;
            }

            // this fd is relevant to us.
            proxy_set(e, e->args.return_code, proxy);
        }
    } 
    else { 
        boe = e->args.a0;
        ba = e->args.a1;
    }
#ifdef _SOXY_IPV6_
    else {
        if(e->args.a0 == AF_INET6) {
            e->args.a0 = AF_INET;
            tracy_modify_syscall_args(e->child, __NR_socket, &e->args);
        }
    }
#endif
    return TRACY_HOOK_CONTINUE;
}

static int soxy_hook_connect(struct tracy_event *e)
{
    long flags;
    int fd;
    int nonblocking;
    long ret;

    ret = 0;

    if(e->child->pre_syscall) {
        struct sockaddr_in addr;

        if(
            // check if the size of the address object is correct
            (unsigned long) e->args.a2 == sizeof(struct sockaddr_in) &&
            //(unsigned long) e->args.a2 >= sizeof(struct sockaddr_in) &&
#ifdef _SOXY_IPV6_
            (unsigned long) e->args.a2 <= sizeof(struct sockaddr_in6) &&
#endif

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

            struct tracy_sc_args fcntl_args = {fd, F_GETFL, 0,
                0, 0, 0, 0, 0, 0, 0};
            if (tracy_inject_syscall(e->child, __NR_fcntl, &fcntl_args, &flags)) {
                fprintf(stderr, "F_GETFL failed\n");
                return 0;
            }
            fprintf(stderr, "fcntl returns: %ld\n", flags);

            nonblocking = (flags & O_NONBLOCK) > 0;
            if (nonblocking) {
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

            if (nonblocking) {
                flags = (flags | O_NONBLOCK);

                struct tracy_sc_args fcntl_args = {fd, F_SETFL, flags,
                    0, 0, 0, 0, 0, 0, 0};
                if (tracy_inject_syscall(e->child, __NR_fcntl, &fcntl_args, &ret)) {
                    fprintf(stderr, "F_GETFL failed\n");
                    return 0;
                }
                fprintf(stderr, "fcntl returns: %ld\n", ret);
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
            tracy_modify_syscall_regs(e->child, __NR_connect, &args);
        }
    }
    return 0;
}

static int soxy_hook_close(struct tracy_event *e)
{
    if(e->child->pre_syscall) {
        proxy_t *proxy = proxy_find(e, e->args.a0);
        if(proxy != NULL) {
            if(proxy->map != NULL) {
                long ret;
                // assume it doesn't fail.
                tracy_munmap(e->child, &ret, proxy->map, 0x1000);
                proxy->map = NULL;
            }
            free(proxy);
            proxy_set(e, e->args.a0, NULL);
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    //struct tracy *tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE | TRACY_VERBOSE_SYSCALL | TRACY_VERBOSE_SIGNAL);
    struct tracy *tracy = tracy_init(TRACY_TRACE_CHILDREN);
    (void)argc;

    tracy->se.child_create = &soxy_child_create;

    if(tracy_set_hook(tracy, "socket", &soxy_hook_socket)) {
        fprintf(stderr, "Error hooking socket(2)\n");
        return EXIT_FAILURE;
    }

    if(tracy_set_hook(tracy, "connect", &soxy_hook_connect)) {
        fprintf(stderr, "Error hooking connect(2)\n");
        return EXIT_FAILURE;
    }

    if(tracy_set_hook(tracy, "close", &soxy_hook_close)) {
        fprintf(stderr, "Error hooking close(2)\n");
        return EXIT_FAILURE;
    }

    tracy_exec(tracy, ++argv);

    tracy_main(tracy);
    tracy_free(tracy);
    return 0;
}
