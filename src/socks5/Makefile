CC=gcc
CFLAGS=-std=c99 -pedantic -Wall -Wextra -Werror
CFLAGS+=-D_XOPEN_SOURCE -D_POSIX_C_SOURCE=200809

socks5: socks5.c main.c
	$(CC) $(CFLAGS) -o $@ $^
	
all: socks5
