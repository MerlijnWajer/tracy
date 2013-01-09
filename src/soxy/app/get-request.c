#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    if(argc < 4) {
        fprintf(stderr, "Usage: %s <hostname> <ip> <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int fd, len; struct sockaddr_in addr; char buf[256];

    fd = socket(AF_INET, SOCK_STREAM, 0);

    snprintf(buf, sizeof(buf), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", argv[1]);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(argv[2]);
    addr.sin_port = htons(atoi(argv[3]));

    connect(fd, (struct sockaddr *) &addr, sizeof(addr));

    send(fd, buf, strlen(buf), 0);

    while ((len = recv(fd, buf, 1, 0)) > 0) {
        fwrite(buf, len, 1, stdout);
    }
    close(fd);
    return 0;
}
