/*
 *
    This file is part of Tracy.

    Tracy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tracy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tracy.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../tracy.h"
#include "../ll.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <sys/mman.h>

#include <sys/time.h>
#include <asm/stat.h>

/* TODO
 * We need to think/implement the timezone value for gettimeofday
 * We need to implement clock_getres(2) still
 *
 * http://www.catb.org/esr/time-programming/
 */

#define set_hook(NAME) \
    if (tracy_set_hook(tracy, #NAME, TRACY_ABI_NATIVE, hook_##NAME)) { \
        printf("Could not hook "#NAME" syscall\n"); \
        return EXIT_FAILURE; \
    }

typedef int (*maps_hook) (struct tracy_child *c, char* name, void* start, void* end);

/* address, perms, offset, dev, inode, pathname */
static int parse_maps(struct tracy_child *c, maps_hook hook) {
    char proc_maps_path[19];
    FILE* fd;

    /* TODO: Put the char* on stack instead of heap? */
    char *buf, *flags, *dev, *pathname;
    long inode;
    unsigned int start, end, offset;

    sprintf(proc_maps_path, "/proc/%d/maps", c->pid);
    printf("Opening %s\n", proc_maps_path);
    fd = fopen(proc_maps_path, "r");

    buf = malloc(4096 * 10);
    flags = malloc(4);
    dev = malloc(5);
    pathname = malloc(4096 * 10);

    while (fgets(buf, 4096 * 10, fd) != NULL) {
        sscanf(buf, "%x-%x %4s %x %5s %ld %s", &start, &end, flags, &offset,
                dev, &inode, pathname);
        printf("start: %x, end: %x, flags: %4s, offset: %x, dev: %5s,"
                "inode: %ld, path: %s\n", start, end, flags, offset, dev, inode, pathname);
        if (hook) {
            if (hook(c, pathname, (void*)start, (void*)end) < 0)
                return -1;
        }
    }

    free(buf);
    free(flags);
    free(dev);
    free(pathname);

    return 0;
}

int vdso_map_hook(struct tracy_child *c, char* name, void* start, void* end) {
    printf("Hook name: %s\n", name);
    printf("Hook start: %p\n", start);
    printf("Hook end: %p\n", end);

    if (strcmp(name, "/bin/ls") == 0) {
        long sysnum;
        long ret;
        struct tracy_sc_args a;

        a = c->event.args;

        a.a0 = (long) start;
        a.a1 = (unsigned long)end - (unsigned long)start;
        a.a2 = PROT_NONE;

        printf("MATCH\n");

        sysnum = get_syscall_number_abi("mprotect", TRACY_ABI_NATIVE);
        printf("sysnum: %ld\n", sysnum);
        printf("addr: %p\n", (void*)a.a0);
        printf("len: %ld\n", a.a1);
        printf("prot: %ld\n", a.a2);
        /* mprotect or munmap */
        tracy_inject_syscall(c, sysnum, &a, &ret);

        printf("tracy_inject_syscall returned: %d\n", (int)ret);

        parse_maps(c, NULL);
    }

    return 0;
}

int hook_SYSCALL_BASE(struct tracy_event *e) {
    parse_maps(e->child, NULL);
    tracy_debug_current(e->child);
    printf("SYSCALL_BASE: pre: %d\n", e->child->pre_syscall);

    return TRACY_HOOK_CONTINUE;
}

int hook_brk(struct tracy_event *e) {
    if (e->child->pre_syscall && e->child->custom) {
        printf("brk: pre: %d\n", e->child->pre_syscall);
        e->child->custom = NULL;
        parse_maps(e->child, vdso_map_hook);
    }

    return TRACY_HOOK_CONTINUE;
}

int hook_execve(struct tracy_event *e) {
    printf("execve: pre: %d\n", e->child->pre_syscall);
    e->child->custom = (void*)!NULL;
    parse_maps(e->child, NULL);
    return TRACY_HOOK_CONTINUE;
}

int hook_open(struct tracy_event *e) {
    printf("open: e->child->pre_syscall: %d\n", e->child->pre_syscall);

    if (e->child->pre_syscall) {
        e->child->custom = (void*) tracy_read_string(e->child, (tracy_child_addr_t)e->args.a0);
    } else {
        if (e->child->custom) {
            printf("open: %s → %ld\n", (char*)e->child->custom, e->args.return_code);
            free(e->child->custom);
            e->child->custom = NULL;
        }
    }

    return TRACY_HOOK_CONTINUE;
}

int hook_time(struct tracy_event *e) {
    time_t t;

    if (e->child->pre_syscall) {
        e->child->custom = (void*)e->args.a0;
    } else {
        t = 42;
        if (e->child->custom) {
            tracy_write_mem(e->child, (tracy_child_addr_t)e->child->custom,
                    (tracy_parent_addr_t)&t, sizeof(time_t));
        }

        e->args.return_code = t;
    }
    return TRACY_HOOK_CONTINUE; 
}

int hook_clock_gettime(struct tracy_event *e) {
    struct timespec tp = {2000, 0};
    int err;

    if (e->child->pre_syscall) {
        if (e->args.a0 == CLOCK_REALTIME || e->args.a0 == CLOCK_REALTIME_COARSE) {
            e->child->custom = (void*)e->args.a1;
        } else {
            e->child->custom = NULL;
        }
    } else {
        if (e->child->custom) {
            err = tracy_write_mem(e->child, (tracy_child_addr_t)e->child->custom,
                    (tracy_parent_addr_t)&tp, sizeof(struct timespec));

            if (err < 0) {
                fprintf(stderr, "tracy_write_mem returned %d\n", err);
                tracy_kill_child(e->child);
            }
        }
    }

    return TRACY_HOOK_CONTINUE; 
}

int hook_gettimeofday(struct tracy_event *e) {
    struct timeval tv = {1700, 0};
    int err;

    if (e->child->pre_syscall) {
        e->child->custom = (void*)e->args.a0;
    } else {
        if (e->child->custom) {
            err = tracy_write_mem(e->child, (tracy_child_addr_t)e->child->custom,
                    (tracy_parent_addr_t)&tv, sizeof(struct timeval));
            if (err < 0) {
                fprintf(stderr, "tracy_write_mem returned %d\n", err);
                tracy_kill_child(e->child);
            }
        }
    }

    return TRACY_HOOK_CONTINUE; 
}


/*
 * {"statfs", (0 + 99)},
 * {"fstatat64", (0 +327)},
 * {"lstat64", (0 +196)},
 * {"fstat64", (0 +197)},
 * {"fstatfs", (0 +100)},
 * {"statfs64", (0 +266)},
 * {"lstat", (0 +107)},
 * {"fstatfs64", (0 +267)},
 * {"stat", (0 +106)},
 * {"stat64", (0 +195)},
 * {"ustat", (0 + 62)},
 * {"fstat", (0 +108)},
 */
#define stat_str stat64

int hook_fstat64(struct tracy_event *e) {
    struct stat_str st;
    int ret;
    struct timespec ts = {0, 0};

    /*fprintf(stderr, "hook_fstat64\n");*/
    if (e->child->pre_syscall) {
        e->child->custom = (void*)e->args.a1;
        /*fprintf(stderr, "fd/ptr: %lx\n", e->args.a0);*/
    } else {
        if (e->child->custom && !e->args.return_code) {
            ret = tracy_read_mem(e->child, (tracy_parent_addr_t)&st,
                                (tracy_child_addr_t)e->child->custom,
                                sizeof(struct stat_str));
            if (ret != sizeof(struct stat_str)) {
                fprintf(stderr, "tracy_read_mem failed: %d\n", ret);
                return TRACY_HOOK_CONTINUE;
            } else {
                /*st.st_mode = 0;*/
                st.st_mtime = ts.tv_sec;
                st.st_atime = ts.tv_sec;
                st.st_ctime = ts.tv_sec;
                ret = tracy_write_mem(e->child, (tracy_child_addr_t)e->child->custom,
                        (tracy_parent_addr_t)&st, sizeof(struct stat_str));
                if (ret != sizeof(struct stat_str)) {
                    fprintf(stderr, "tracy_read_mem failed: %d\n", ret);
                }
            }

        }
    }
    return TRACY_HOOK_CONTINUE; 
}

int hook_stat64(struct tracy_event *e) {
    /*fprintf(stderr, "hook_stat64 -> hook_fstat64\n");*/
    return hook_fstat64(e);
}

int hook_lstat64(struct tracy_event *e) {
    /*fprintf(stderr, "hook_lstat64 -> hook_fstat64\n");*/
    return hook_fstat64(e);
}


int main(int argc, char** argv) {
    struct tracy *tracy;

    /* Tracy options */
#if 0
    tracy = tracy_init(TRACY_TRACE_CHILDREN);
#endif
    tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE |
            TRACY_VERBOSE_SIGNAL | TRACY_VERBOSE_SYSCALL);

    if (argc < 2) {
        printf("Usage: ./example <program-name|pid> [arguments]\n");
        return EXIT_FAILURE;
    }

    /* Hooks */

    set_hook(SYSCALL_BASE);
    set_hook(brk);
    set_hook(execve);
    set_hook(open);
    set_hook(time);
    set_hook(clock_gettime);
    set_hook(gettimeofday);
    set_hook(stat64);
    set_hook(lstat64);
    set_hook(fstat64);

    argv++; argc--;

    /* Start child */
    if (!tracy_exec(tracy, argv)) {
        perror("tracy_exec");
        return EXIT_FAILURE;
    }

    /* Main event-loop */
    tracy_main(tracy);

    tracy_free(tracy);

    return EXIT_SUCCESS;
}
