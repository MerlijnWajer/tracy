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

#define set_hook(NAME) \
    if (tracy_set_hook(tracy, #NAME, TRACY_ABI_NATIVE, hook_##NAME)) { \
        printf("Could not hook "#NAME" syscall\n"); \
        return EXIT_FAILURE; \
    }

int hook_write(struct tracy_event *e) {
    long ret;
    int i;

    char *s;
    int count, rc;

    if (e->child->pre_syscall) {
        count = e->args.a2;
        s = malloc(sizeof(char)*(count+1));
        rc = tracy_read_mem(e->child, s, (tracy_child_addr_t)e->args.a1, count);
        s[count] = '\0';
        /*printf("tracy_read_mem returned: %d\n", rc);*/

        for(i = 0; i < count >> 1; i++) {
            s[i] ^= s[count-i];
            s[count-i] ^= s[i];
            s[i] ^= s[count-i];
        }

        rc = tracy_write_mem(e->child, (tracy_child_addr_t)e->args.a1,
                (tracy_parent_addr_t) s, count * sizeof(char));
        /*printf("tracy_write_mem returned: %d\n", rc);*/


        /*tracy_inject_syscall(e->child, __NR_write, &(e->args), &ret);*/
        /*printf("wr Return code: %ld\n", ret);*/
        (void)ret;
        (void)rc;

        free(s);
    } else {
    }
    return TRACY_HOOK_CONTINUE;
}

int main(int argc, char** argv) {
    struct tracy *tracy;

    /* Tracy options */
    tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE);

    if (argc < 2) {
        printf("Usage: ./tracy-inject-simple <program-name>\n");
        return EXIT_FAILURE;
    }

    /* Hooks */
    set_hook(write);

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
