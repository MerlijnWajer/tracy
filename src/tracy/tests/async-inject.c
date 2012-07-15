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

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>
#include <unistd.h>

int _write(struct tracy_event *e, void *data) {
    (void)data;
    if (e->child->inj.injected) {
        printf("We just injected something. Result: %ld\n", e->args.return_code);
        return 0;
    }
    if (e->child->pre_syscall) {
        printf("Pre-async inject\n");
        if (tracy_inject_syscall_pre_start(e->child, __NR_write,
                &(e->args), &_write, NULL))
            return TRACY_HOOK_ABORT;
    } else {
        printf("Post-async inject\n");
        if (tracy_inject_syscall_post_start(e->child, __NR_write,
                &(e->args), &_write, NULL))
            return TRACY_HOOK_ABORT;
    }

    return 0;
}

int main(int argc, char** argv) {
    struct tracy *tracy;

    /* Tracy options */
    tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE |
            TRACY_VERBOSE_SIGNAL | TRACY_VERBOSE_SYSCALL);

    tracy_set_hook(tracy, "write", &_write, NULL);

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
