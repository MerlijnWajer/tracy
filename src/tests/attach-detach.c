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

int hook(struct tracy_event *e) {
    (void)e;
    puts("Hooked a system call. Detaching...");
    /*tracy_detach_child(e->child);*/

    return TRACY_HOOK_DETACH_CHILD;
}

int main(int argc, char** argv) {
    struct tracy *tracy;
    pid_t pid;
    char *endptr;

    /* Tracy options */
    #if 0
    tracy = tracy_init(TRACY_TRACE_CHILDREN);
    #else
    tracy = tracy_init(TRACY_TRACE_CHILDREN);
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

    /* Start child */
    if (!tracy_attach(tracy, pid)) {
        perror("tracy_attach");
        tracy_free(tracy);
        return EXIT_FAILURE;
    }

    tracy_set_hook(tracy, "write", TRACY_ABI_NATIVE, hook);
    /*tracy_set_default_hook(tracy, hook);*/

    /* Main event-loop */
    tracy_main(tracy);

    /* Clean up */
    tracy_free(tracy);

    return EXIT_SUCCESS;
}
