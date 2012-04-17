#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "tracy.h"
#include "ll.h"
#include "socks5/socks5.h"

#include <sys/syscall.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <linux/net.h>

static int soxy_inject_socketcall(struct tracy_child *child, int nr, long args[6])
{
	void *addr; struct tracy_sc_args real_args; long dummy, retcode;

	// write the arguments to the child
	tracy_mmap(child, (long *) &addr, NULL, sizeof(args), PROT_READ | PROT_WRITE,
		MAP_PRIVATE, -1, 0);
	tracy_write_mem(child, addr, args, sizeof(args));

	// execute the syscall
	memset(&real_args, 0, sizeof(real_args));
	real_args.a0 = nr;
	real_args.a1 = (long) addr;
	tracy_inject_syscall(child, __NR_socketcall, &real_args, &retcode);

	// delete memory in child
	tracy_munmap(child, &dummy, addr, sizeof(args));
	return retcode;
}

static int soxy_socket(struct _socks5_t *s5, int socket_family,
	int socket_type, int protocol)
{
	long retcode, args[6] = {
		socket_family, socket_type, protocol
	};
	retcode = soxy_inject_socketcall(s5->arg, SYS_SOCKET, args);
	return retcode;
}

static int soxy_connect(struct _socks5_t *s5, int sockfd,
	const struct sockaddr *addr, socklen_t addrlen)
{
	// TODO: copy `struct sockaddr' to child
	long retcode, args[6] = {
		sockfd, (long) addr, addrlen
	};
	retcode = soxy_inject_socketcall(s5->arg, SYS_CONNECT, args);
	return retcode;
}

static ssize_t soxy_send(struct _socks5_t *s5, int sockfd, const void *buf,
	size_t len, int flags)
{
	// TODO: copy `buf' to child
	long retcode, args[6] = {
		sockfd, (long) buf, len, flags
	};
	retcode = soxy_inject_socketcall(s5->arg, SYS_SEND, args);
	return retcode;
}

static ssize_t soxy_sendto(struct _socks5_t *s5, int sockfd, const void *buf,
	size_t len, int flags, const struct sockaddr *dest_addr,
	socklen_t addrlen)
{
	(void)s5; (void)sockfd; (void)buf; (void)len; (void)flags;
	(void)dest_addr; (void)addrlen;
	return 0;
}

static ssize_t soxy_recv(struct _socks5_t *s5, int sockfd, void *buf,
	size_t len, int flags)
{
	// TODO: copy `buf' from child
	long retcode, args[6] = {
		sockfd, (long) buf, len, flags
	};
	retcode = soxy_inject_socketcall(s5->arg, SYS_RECV, args);
	return retcode;
}
	
static ssize_t soxy_recvfrom(struct _socks5_t *s5, int sockfd, void *buf,
	size_t len, int flags, struct sockaddr *src_addr,
	socklen_t *addrlen)
{
	(void)s5; (void)sockfd; (void)buf; (void)len; (void)flags;
	(void)src_addr; (void)addrlen;
	return 0;
}
	
static int soxy_close(struct _socks5_t *s5, int fd)
{
	long retcode; struct tracy_sc_args args = {
		fd, 0, 0, 0, 0, 0, 0, 0, 0, 0
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

static int soxy_hook_socketcall(struct tracy_event *e)
{
	static long args[6] = {};
	if(e->child->pre_syscall) {
		// read the arguments (located in a1)
		tracy_read_mem(e->child, args, (void *) e->args.a1, sizeof(args));
		switch (e->args.a0) {
		case SYS_SOCKET:
			if(args[0] == SOCK_STREAM) {
				aup = socks5_init(&soxy_api, e->child);
				return 0;
			}
			return -1;

		case SYS_CONNECT:
			socks5_set_server(aup, "localhost", 8888);
			socks5_connect_proxy_server(aup);
			// ipv4
			if(args[0] == AF_INET) {
				// TODO: copy `struct sockaddr' to parent process
				socks5_proxy_ipv4(aup, (struct sockaddr_in *) args[1]);
				return 0;
			}
			return -1;
		}
	}
	else {
		switch (e->args.a0) {
		case SYS_SOCKET:
			e->args.return_code = aup->fd;
			return 0;
		}
	}
	return -1;
}

static int soxy_hook_close(struct tracy_event *e)
{
	printf("le close?\n");
	if(!e->child->pre_syscall) {
		// free stuff..
	}
	return 0;
}

int main(int argc, char *argv[])
{
	(void)argc; (void)argv;

	struct tracy *tracy = tracy_init();

	tracy_set_hook(tracy, "close", &soxy_hook_close);
	tracy_set_hook(tracy, "socketcall", &soxy_hook_socketcall);
	
	struct tracy_child *child = fork_trace_exec(tracy, argc-1, argv+1);
	
	// all tracy logic goes in a nice loop
	tracy_main(tracy);

	tracy_free(tracy);
	return 0;
}

