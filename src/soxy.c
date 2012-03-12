#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "tracy.h"
#include "ll.h"
#include "socks5/socks5.h"

#include <sys/syscall.h>
#include <asm/unistd.h>

static int soxy_socket(struct _socks5_t *s5, int socket_family,
	int socket_type, int protocol)
{
	long retcode; struct tracy_sc_args args = {
		socket_family, socket_type, protocol,
	};
	tracy_inject_syscall(s5->arg, __NR_socket, &args, &retcode);
	return retcode;
}

static int soxy_connect(struct _socks5_t *s5, int sockfd,
	const struct sockaddr *addr, socklen_t addrlen)
{
	// TODO: copy `struct sockaddr' to child
	long retcode; struct tracy_sc_args args = {
		sockfd, addr, addrlen,
	};
	tracy_inject_syscall(s5->arg, __NR_connect, &args, &retcode);
	return retcode;
}

static ssize_t soxy_send(struct _socks5_t *s5, int sockfd, const void *buf,
	size_t len, int flags)
{
	// TODO: copy `buf' to child
	long retcode; struct tracy_sc_args args = {
		sockfd, buf, len, flags,
	};
	tracy_inject_syscall(s5->arg, __NR_send, &args, &retcode);
	return retcode;
}

static ssize_t soxy_sendto(struct _socks5_t *s5, int sockfd, const void *buf,
	size_t len, int flags, const struct sockaddr *dest_addr,
	socklen_t addrlen)
{
}

static ssize_t soxy_recv(struct _socks5_t *s5, int sockfd, void *buf,
	size_t len, int flags)
{
	// TODO: copy `buf' from child
	long retcode; struct tracy_sc_args args = {
		sockfd, buf, len, flags,
	};
	tracy_inject_syscall(s5->arg, __NR_recv, &args, &retcode);
	return retcode;
}
	
static ssize_t soxy_recvfrom(struct _socks5_t *s5, int sockfd, void *buf,
	size_t len, int flags, struct sockaddr *src_addr,
	socklen_t *addrlen)
{

}
	
static int soxy_close(struct _socks5_t *s5, int fd)
{
	long retcode; struct tracy_sc_args args = {
		fd
	};
	tracy_inject_syscall(s5->arg, __NR_close, &args, &retcode);
	return retcode;
}

static socks5_api_t soxy_api = {
	&soxy_socket,
	&soxy_connect,
	&soxy_send,
	&soxy_sendto,
	&soxy_recv,
	&soxy_recvfrom,
	&soxy_close,
};

// TODO: `tracy_child' needs an array of `fd' for mapping fd to `socks5_t'
socks5_t *aup;

//
// We use the `arg' value in `socks5_t' to store the
// `struct tracy_child' object pointer
//

static int soxy_hook_socket(struct tracy_event *e)
{
	if(e->child->pre_syscall) {
		// does the application want a TCP socket?
		if(e->args.a1 == SOCK_STREAM) {
			socks5_t *s5 = socks5_init(&soxy_api, e->child);
			aup = s5;		
			return 0;
		}
		return -1;
	}
	else {
		// set the return value
		e->args.return_code = aup->fd;
	}
	return 0;
}

static int soxy_hook_connect(struct tracy_event *e)
{
	if(e->child->pre_syscall) {
		socks5_set_server(aup, "localhost", 8888);
		socks5_connect_proxy_server(aup);
		// ipv4
		if(e->args.a0 == AF_INET) {
			// TODO: copy `struct sockaddr' to parent process
			socks5_proxy_ipv4(aup, e->args.a1);
			return 0;
		}
		return -1;
	}
	return 0;
}

static int soxy_hook_close(struct tracy_event *e)
{
	if(!e->child->post_syscall) {
		// free stuff..
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct tracy *tracy = tracy_init();
	
	tracy_set_hook(tracy, "socket", &soxy_hook_socket);
	tracy_set_hook(tracy, "connect", &soxy_hook_connect);
	tracy_set_hook(tracy, "close", &soxy_hook_close);
	
	// all tracy logic goes in a nice loop
	tracy_main(tracy);

	tracy_free(tracy);
	return 0;
}

