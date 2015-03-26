/*
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

#include <stdio.h>
#include <stdlib.h>

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>
#include <unistd.h>

#include <sys/mman.h>

int inject_execve(struct tracy_event *e) {
    struct tracy_sc_args a;
    tracy_child_addr_t mmap_ret = NULL;
    long ret;
    char *s;

    ret = tracy_mmap(e->child, &mmap_ret, NULL, 4096, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    tracy_write_mem(e->child, mmap_ret, (tracy_parent_addr_t)"/bin/ls", 8 * sizeof(char));
    /*tracy_write_mem(e->child, mmap_ret, (tracy_parent_addr_t)"/usr/bin/wmii", 15 * sizeof(char));*/

    printf("Tracy ret: %ld\n", ret);
    printf("Tracy ptr: %lx\n", (unsigned long)mmap_ret);

    s = malloc(sizeof(char) * 8);
    tracy_read_mem(e->child, (tracy_parent_addr_t)s, mmap_ret, 8 * sizeof(char));
    printf("String: %s\n", s);


    a.a0 = (unsigned long) mmap_ret;
    a.a1 = (long) NULL;
    a.a2 = (long) NULL;

    /*
   int execve(const char *filename, char *const argv[],
                     char *const envp[]);*/


    tracy_inject_syscall(e->child, __NR_execve, &a, &ret);
    printf("Return code: %ld\n", ret);

    return TRACY_HOOK_CONTINUE;
}

int main(int argc, char** argv) {
    struct tracy *tracy;
    pid_t pid;
    char *endptr;

    /* Tracy options */
    #if 0
    tracy = tracy_init(TRACY_TRACE_CHILDREN);
    #else
    tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE | TRACY_VERBOSE_SYSCALL | TRACY_VERBOSE_SIGNAL);
    #endif

    /* Only a PID is required */
    if (argc != 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* Parse PID */
    pid = (int)strtol(argv[1], &endptr, 10);
    if (endptr[0]) {
        fprintf(stderr, "Invalid PID value\n");
        tracy_free(tracy);
        return EXIT_FAILURE;
    }

    tracy_set_default_hook(tracy, inject_execve);

    /* Start child */
    if (!tracy_attach(tracy, pid)) {
        perror("tracy_attach");
        tracy_free(tracy);
        return EXIT_FAILURE;
    }

    /* Main event-loop */
    tracy_main(tracy);

    /* Clean up */
    tracy_free(tracy);

    return EXIT_SUCCESS;
}
