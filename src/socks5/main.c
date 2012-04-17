#include <stdio.h>
#include <string.h>
#include "socks5.h"

int main()
{
	socks5_t *s5 = socks5_init(NULL, NULL);
	socks5_set_server(s5, "localhost", 8888);
	printf("connect-server: %d\n", socks5_connect_proxy_server(s5));
	// printf("proxy: %d\n", socks5_proxy_hostname(s5, "www.google.com", 80));
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = (106 << 24) + (79 << 16) + (125 << 8) + 74;
	addr.sin_port = htons(80);
	printf("proxy: %d\n", socks5_proxy_ipv4(s5, &addr));
	perror("bla2");
	char buf[] = "GET /\r\nHost: www.google.com\r\n\r\n";
	send(s5->fd, buf, strlen(buf), 0);
	while (recv(s5->fd, buf, sizeof(buf), 0)) {
		fwrite(buf, sizeof(buf), 1, stdout);
	}
	socks5_free(s5);
}
