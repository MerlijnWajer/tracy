#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../ll.h"
#include "../tracy.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <ctype.h>

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>

void cat_file(char *file);

/* write syscall hook args layout:
 *      e->args.a0: file descriptor
 *      e->args.a1: data pointer
 *      e->args.a2: data length
 */
int foo(struct tracy_event *e) {
    int len, i;
    char *str;
    long word;
    char wstr[5];
    char child_maps_path[20];

    static int dump_maps_once = 1;

    if (!e->child->pre_syscall)
        return 0;

    if (dump_maps_once) {
        sprintf(child_maps_path, "/proc/%i/maps", e->child->pid);
        cat_file(child_maps_path);
        perror(child_maps_path);
        dump_maps_once = 0;
    }

#if 0
    printf("In hook for function call \"write\"(%ld)\n", e->syscall_num);
    printf("Argument 0 (fd) for write: %ld\n", e->args.a0);
    printf("Argument 1 (str) for write: %p\n", (void*)e->args.a1);
    printf("Argument 2 (len) for write: %ld\n", e->args.a2);
#endif

    len = e->args.a2;
    str = malloc(sizeof(char) * 4096);

    /* Read memory */
    if ((i = tracy_read_mem(e->child, str, (void*)e->args.a1, sizeof(char) * len)) < 0)
        perror("tracy_read_mem");
    printf("Read %d bytes.\n", i);

    /* Python style string dump */
    if (i > 0) {
        printf("Data: '");
        for (i = 0; i < len; i++) {
            if (isprint(str[i]))
                printf("%c", str[i]);
            else
                printf("\\x%02x", str[i] & 0xff);
        }
        printf("'\n");
    }

    /* Peek single word at same address */
    if(tracy_peek_word(e->child, e->args.a1, &word) < 0)
        perror("tracy_peek_word");

    for (i = 0; i < 4; i++)
        wstr[i] = (char)((word >> i * 8) & 0xff);

    wstr[i] = '\0';
    printf("Data by peek word: %p, '%s'\n", (void*)word, wstr);

    strfry(str);
    if (tracy_write_mem(e->child, (void*)e->args.a1, str, sizeof(char) * len) < 0)
        perror("tracy_write_mem");

    free(str);

    word = 0x6f6c6f6c; /* "lolo" */
    if (tracy_poke_word(e->child, e->args.a1, word) < 0)
        perror("tracy_poke_word");

#if 0
    e->args.a2 = strlen(newmsg);

    /*
     * This will not work, because the child cannot access our memory.
     * SHM?
     */
/*    e->args.a1 = (long)stephen; */

    /* This is allowed, of course */
    e->args.a2 = strlen(stephen);

    printf("Modify_registers: %d.\n", modify_registers(e));

    /* Don't let flushing bully us */
    fflush(NULL);
#endif

    return 0;
}

void cat_file(char *file)
{
    int r;
    int fd;
    char buf[128];

    fd = open(file, O_RDONLY, 0);
    if (fd < 0)
        return;

    while ((r = read(fd, buf, 128)) > 0)
        fwrite(buf, 1, r, stdout);

    close(fd);
    return;
}

int main(int argc, char** argv) {
    struct tracy *tracy;
    struct tracy_event *e;

    tracy = tracy_init();

    if (argc < 2) {
        printf("Usage: soxy <program name> <program arguments>\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "write", foo)) {
        printf("Failed to hook write syscall.\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;
    if (!fork_trace_exec(tracy, argc, argv)) {
        perror("fork_trace_exec returned NULL");
        return EXIT_FAILURE;
    }

    while (1) {
        e = tracy_wait_event(tracy);

        /* Handle events */

        /* If the (last) child died, break */
        if (e->type == TRACY_EVENT_NONE) {
            /* puts("We're done"); */
            break;
        }

        if (e->type == TRACY_EVENT_SIGNAL) {
            printf("Signal %ld for child %d\n", e->signal_num, e->child->pid);
        }

        if (e->type == TRACY_EVENT_SYSCALL) {
            if (e->child->pre_syscall) {
                /*
                printf("PRE Syscall %s (%ld) requested by child %d, IP: %ld\n",
                    get_syscall_name(e->syscall_num), e->syscall_num,
                    e->child->pid, e->args.ip);
                */
                if (get_syscall_name(e->syscall_num))
                    if(!tracy_execute_hook(tracy,
                                get_syscall_name(e->syscall_num), e)) {
                    }
            } else {
                /*
                printf("POST Syscall %s (%ld) requested by child %d, IP: %ld\n",
                    get_syscall_name(e->syscall_num), e->syscall_num,
                        e->child->pid, e->args.ip);
                */
                if (get_syscall_name(e->syscall_num))
                    tracy_execute_hook(tracy, get_syscall_name(e->syscall_num),
                            e);
            }
        }

        if (e->type == TRACY_EVENT_QUIT) {
            printf("\nEVENT_QUIT from %d with signal %ld\n", e->child->pid,
                    e->signal_num);
            if (e->child->pid == tracy->fpid) {
                printf("Our first child died.\n");
            }
        }

        tracy_continue(e);
    }

    tracy_free(tracy);

    return 0;
}
