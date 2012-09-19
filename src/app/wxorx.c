#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "ll.h"
#include "tracy.h"

#include <sys/syscall.h>

#include <errno.h>

struct tracy_child_mem {
    long start, size;
    long perms;
    long offset;
};

/* void *mmap(void *addr, size_t length, int prot, int flags,
                                 int fd, off_t offset); */
int hook_mmap(struct tracy_event *e) {
    (void) e;

    return TRACY_HOOK_CONTINUE;
}

/* int munmap(void *addr, size_t length); */
int hook_munmap(struct tracy_event *e) {
    (void) e;

    return TRACY_HOOK_CONTINUE;
}

/* address, perms, offset, dev, inode, pathname */
static int parse_maps(struct tracy_child *c) {
    char proc_maps_path[19];
    FILE* fd;

    char *buf, *num;
    int i, j;

    sprintf(proc_maps_path, "/proc/%d/maps", c->pid);
    printf("Opening %s\n", proc_maps_path);
    fd = fopen(proc_maps_path, "r");

    buf = malloc(4096 * 10);
    num = malloc(40);

    while (fgets(buf, 4096 * 10, fd) != NULL) {
        printf("Line: %s", buf);
        i = 0;
        while(buf[i] != '-') {
            num[i] = buf[i];
            i++;
        }
        num[i] = '\0';

        i++;
        j = 0;

        printf("Start: %ld\n", strtol(num, NULL, 16));
        while(buf[i] != ' ') {
            num[j] = buf[i];
            i++;
            j++;
        }
        num[j] = '\0';

        printf("End: %ld\n", strtol(num, NULL, 16));
    }

    return 0;
}

static void child_create(struct tracy_child *child) {
    child->custom = ll_init();
    puts("New child!");
    parse_maps(child);
    /* child->mem_fallback = 1; */
}

int main (int argc, char** argv) {
    struct tracy *tracy;

    tracy = tracy_init(TRACY_TRACE_CHILDREN);


    /* Set hooks here */
    tracy->se.child_create = &child_create;

    if (tracy_set_hook(tracy, "mmap", hook_mmap)) {
        printf("failed to hook mmap syscall.\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "munmap", hook_munmap)) {
        printf("failed to hook mmap syscall.\n");
        return EXIT_FAILURE;
    }

    /* Execute program */
    argv++; argc--;
    if (!tracy_exec(tracy, argv)) {
        perror("tracy_exec returned NULL");
        return EXIT_FAILURE;
    }

    tracy_main(tracy);
    tracy_free(tracy);

    return EXIT_SUCCESS;
}
