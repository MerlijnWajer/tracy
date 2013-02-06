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
    char *buf;
    unsigned long sysinstr;

    /* s->child->mem_fallback = 1; */
    buf = malloc(sizeof(char) * sizeof(unsigned long));
    tracy_read_mem(s->child, buf, (char*)s->args.ip - TRACY_SYSCALL_OPSIZE,
            sizeof(char) * TRACY_SYSCALL_OPSIZE);

    sysinstr = *(unsigned long*)buf & 0x0000FFFF;
    if (s->child->pre_syscall) {
        printf("Pre. IP: %lx: %lx\n", s->args.ip, sysinstr);
        if (sysinstr == 0x50f) {
            puts("64 bit");
        } else if (sysinstr == 0x80cd) {
            puts("32 bit");
        }
    }


    free(buf);

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
