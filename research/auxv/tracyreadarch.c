#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "tracy.h"

static char *pidptr;

void readarch(struct tracy_child *c, char* pid) {
    char* file = malloc(sizeof(char)*1024);
    sprintf(file, "/proc/%s/auxv", pid);
    printf("Filename: %s\n", file);
    FILE *f = fopen(file, "r");
    long *buf = malloc(1024*sizeof(char));
    printf("Read: %ld bytes\n", fread(buf, 4, 1000, f));

    while (!(buf[0] ==0 && buf[1] == 0)) {
        if (buf[0] == 15) {
            char *archbuf;
            archbuf = tracy_read_string(c, (void*)buf[1]);
            printf("Arch: %s\n", archbuf);
        }
        buf+=2;
    }
    fclose(f);
}

void readarch32(struct tracy_child *c, char* pid) {
    char* file = malloc(sizeof(char)*1024);
    sprintf(file, "/proc/%s/auxv", pid);
    printf("Filename: %s\n", file);
    FILE *f = fopen(file, "r");
    uint32_t *buf = malloc(1024*sizeof(char));
    printf("Read: %ld bytes\n", fread(buf, 2, 1000, f));

    while (!(buf[0] ==0 && buf[1] == 0)) {
        if (buf[0] == 15) {
            char *archbuf;
            archbuf = tracy_read_string(c, (void*)buf[1]);
            printf("Arch: %s\n", archbuf);
        }
        buf+=2;
    }
    fclose(f);
}

int defhook(struct tracy_event *e) {
    readarch(e->child, pidptr);
    readarch32(e->child, pidptr);

    return TRACY_HOOK_ABORT;
}

int main(int argc, char** argv) {
    struct tracy *tracy;
    char* endptr;
    pid_t pid;

    tracy = tracy_init(TRACY_TRACE_CHILDREN);

    pidptr = argv[1];
    pid = (int)strtol(argv[1], &endptr, 10);

    tracy_set_default_hook(tracy, defhook);

    tracy_attach(tracy, pid);
    tracy_main(tracy);

    tracy_free(tracy);
    return 0;
}
