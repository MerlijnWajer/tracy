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
#include "../ll.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>
#include <unistd.h>

int hook_write(struct tracy_event *e, void *data) {
    (void)data;
    if (e->child->pre_syscall) {
        if(e->args.a0 == 1) {
            tracy_deny_syscall(e->child);
            printf("Denying write to stdout\n");
        }
    } else {
    }

    return TRACY_HOOK_CONTINUE;
}

int main(int argc, char** argv) {
    struct tracy *tracy;

    /* Tracy options */
    /*tracy = tracy_init(TRACY_TRACE_CHILDREN);*/
    tracy = tracy_init(TRACY_TRACE_CHILDREN);

    if (tracy_set_hook(tracy, "write", hook_write, NULL)) {
        fprintf(stderr, "Could not hook getpid\n");
        return EXIT_FAILURE;
    }

    if (argc < 2) {
        printf("Usage: ./example <program-name>\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;

    /* Start child */
    if (!fork_trace_exec(tracy, argc, argv)) {
        perror("fork_trace_exec");
        return EXIT_FAILURE;
    }

    /* Main event-loop */
    tracy_main(tracy);

    tracy_free(tracy);

    return EXIT_SUCCESS;
}
