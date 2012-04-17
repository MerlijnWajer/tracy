#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

int main()
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	char buf[] = "GET / HTTP/1.0\r\nHost: www.google.com\r\n\r\n";
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = (106 << 24) + (79 << 16) + (125 << 8) + 74;
	addr.sin_port = htons(80);
	connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	send(fd, buf, strlen(buf), 0);
	while (recv(fd, buf, 1, 0) > 0) {
		fwrite(buf, 1, 1, stdout);
	}
	close(fd);
	return 0;
}
