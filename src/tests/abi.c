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

int abi_detect(struct tracy_event *s) {
#ifdef __x86_64__
    struct TRACY_REGS_NAME a;
#endif

#ifdef __i386__
    puts("x86");
    return TRACY_HOOK_CONTINUE;
#endif


#ifdef __x86_64__
    PTRACE_CHECK(PTRACE_GETREGS, s->child->pid, 0, &a, -1);
    if (a.cs == 0x33) {
        puts("amd64");
    } else if(a.cs == 0x23) {
        puts("x86");
    }
#endif
    tracy_debug_current_pid(s->child->pid);

    return TRACY_HOOK_CONTINUE;
}

int main(int argc, char** argv) {
    struct tracy *tracy;

    /* Tracy options */
    tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_MEMORY_FALLBACK);
    /*
    tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE |
            TRACY_VERBOSE_SIGNAL | TRACY_VERBOSE_SYSCALL);
            */

    if (argc < 2) {
        printf("Usage: ./example <program-name>\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;

    tracy_set_default_hook(tracy, abi_detect);

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
