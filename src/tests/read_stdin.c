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

#include <string.h>

int prev = 0;

int hook_read(struct tracy_event *e) {
    char *buf;
    size_t bufsize;

    if (e->child->pre_syscall) {
        if (e->args.a0 == 0) {
            e->child->custom = (void*)e->args.a1;
            prev = 1;
        } else {
            prev = 0;
        }
    } else {
        if (prev) {
            bufsize = e->args.return_code;

            if ((ssize_t)bufsize < 0) {
                strerror(-bufsize);
                return TRACY_HOOK_CONTINUE;
            }

            buf = malloc(sizeof(char) * (bufsize + 1));

            /*printf("Reading memory now. Count: %d From %lx To %lx\n", bufsize,
                    (long)ptr, (long)buf);
            */

            tracy_read_mem(e->child, buf, e->child->custom, bufsize);

            buf[bufsize-1] = '\0';
            printf("%s\n", buf);

            free(buf);
            
            return TRACY_HOOK_CONTINUE;
        }
    }

    return TRACY_HOOK_CONTINUE;
}

int main(int argc, char** argv) {
    struct tracy *tracy;
    int pid;

    /* Tracy options */
    tracy = tracy_init(TRACY_TRACE_CHILDREN);
    tracy_set_hook(tracy, "read", TRACY_ABI_NATIVE, hook_read);
#ifdef __x86_64__
    tracy_set_hook(tracy, "read", TRACY_ABI_X86, hook_read);
#endif
    /*tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE);*/

    if (argc < 2) {
        printf("Usage: ./example <program-name>\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;
    while(argc--) {
        pid = atoi((const char *)argv[0]);
        printf("Going to attach to %d\n", pid);

        if (!tracy_attach(tracy, pid)) {
            perror("tracy_exec");
            return EXIT_FAILURE;
        }
        argv++;
    }


    /* Main event-loop */
    tracy_main(tracy);

    tracy_free(tracy);

    return EXIT_SUCCESS;
}
