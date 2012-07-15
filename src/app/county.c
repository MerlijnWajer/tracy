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

/*
 * County.
 *
 */

#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracy.h"
#include "ll.h"

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>

#include <errno.h>

struct tracy_ll * ll;

int all(struct tracy_event *e) {
    struct tracy_ll_item *i;
    long syscall;

    if(e->child->pre_syscall)
        return TRACY_HOOK_CONTINUE;

    syscall = e->syscall_num;

    i = ll_find(ll, syscall);
    if (i) {
        i->data = (void*)((long)(i->data) + 1);
    } else {
        ll_add(ll, syscall, (void*)1);
    }

    return TRACY_HOOK_CONTINUE;
}

static void print_stats(void) {
    struct tracy_ll_item *cur;
    cur = ll->head;

    while (cur) {
        printf("Syscall: %s called %ld times.\n", get_syscall_name(cur->id),
                (long)cur->data);

        cur = cur->next;
    }

    return;
}

int main(int argc, char** argv) {
    struct tracy *tracy;

    ll = ll_init();
    tracy = tracy_init(TRACY_TRACE_CHILDREN);

    if (argc < 2) {
        printf("Usage: county <program name> <program arguments>\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_default_hook(tracy, all)) {
        printf("Failed to hook default hook.\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;
    if (!fork_trace_exec(tracy, argc, argv)) {
        perror("fork_trace_exec returned NULL");
        return EXIT_FAILURE;
    }

    tracy_main(tracy);

    tracy_free(tracy);

    print_stats();

    ll_free(ll);

    return 0;
}
