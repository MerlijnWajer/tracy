#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracy.h"
#include "ll.h"

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>

FILE *_stdout, *_stderr;

int log_write(struct tracy_event *e) {
    int len, fd;
    char* str;

    if (!e->child->pre_syscall)
        return 0;

    fd = e->args.a0;

    if (!(fd == 1) && !(fd == 2))
        return 0;

    len = e->args.a2;
    str = malloc(sizeof(char) * len);

    tracy_read_mem(e->child, (void*)str, (void*)e->args.a1, sizeof(char) * len);

    printf("Write call for fd: %ld, str: %s, len: %ld\n",
            e->args.a0, str, e->args.a2);

    if (fd == 1)
        fwrite(str, sizeof(char), len, _stdout);
    if (fd == 2)
        fwrite(str, sizeof(char), len, _stderr);

    free(str);

    return 0;
}

int main(int argc, char** argv) {
    struct tracy *tracy;

    _stdout = fopen("stdout.txt", "w+");
    _stderr = fopen("stderr.txt", "w+");
    if (!_stdout || !_stderr) {
        puts("Can't open files");
        return EXIT_FAILURE;
    }

    tracy = tracy_init(TRACY_TRACE_CHILDREN);

    if (argc < 2) {
        printf("Usage: loggy <program name> <program arguments>\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "write", log_write)) {
        printf("Failed to hook write syscall.\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;
    if (!fork_trace_exec(tracy, argc, argv)) {
        perror("fork_trace_exec returned NULL");
        return EXIT_FAILURE;
    }

    tracy_main(tracy);

    tracy_free(tracy);

    return 0;
}
