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

#include <sys/time.h>

/* TODO
 * For clock_gettime we need to be careful of the clock id -- for monotonic we
 * do not want to touch the values, for example.
 *
 * We need to think/implement the timezone value for gettimeofday
 *
 * We need to implement clock_getres(2) still
 *
 * http://www.catb.org/esr/time-programming/
 */

#define set_hook(NAME) \
    if (tracy_set_hook(tracy, #NAME, TRACY_ABI_NATIVE, hook_##NAME)) { \
        printf("Could not hook "#NAME" syscall\n"); \
        return EXIT_FAILURE; \
    }

/*
int hook_stat(struct tracy_event *e) {
    if (e->child->pre_syscall) {
        e->child->custom = (void*) tracy_read_string(e->child, (tracy_child_addr_t)e->args.a0);
    } else {
        printf("stat: %s → %ld\n", (char*)e->child->custom, e->args.return_code);
    }

    return TRACY_HOOK_CONTINUE;
}
*/

int hook_open(struct tracy_event *e) {
    if (e->child->pre_syscall) {
        e->child->custom = (void*) tracy_read_string(e->child, (tracy_child_addr_t)e->args.a0);
    } else {
        printf("open: %s → %ld\n", (char*)e->child->custom, e->args.return_code);
    }

    return TRACY_HOOK_CONTINUE;
}

int hook_time(struct tracy_event *e) {
    /* TODO: time(2) is broken, needs tracy_modify_args for return_code 
     * and change pointer value */
    if (!e->child->pre_syscall) {
        e->args.return_code = 10000;
    }
    return TRACY_HOOK_CONTINUE; 
}

/* TODO: Only for CLOCK_REALTIME_COARSE CLOCK_REALTIME */
/* TODO: Use same approach as gettimeofday */
int hook_clock_gettime(struct tracy_event *e) {
    struct timespec tp = {2000, 0};
    int err;

    if (e->child->pre_syscall) {
        e->child->custom = (void*)e->args.a1;
    } else {
        err = tracy_write_mem(e->child, (tracy_child_addr_t)e->child->custom,
                (tracy_parent_addr_t)&tp, sizeof(struct timespec));
        if (err < 0) {
            fprintf(stderr, "tracy_write_mem returned %d\n", err);
            tracy_kill_child(e->child);
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
        err = tracy_write_mem(e->child, (tracy_child_addr_t)e->child->custom,
                (tracy_parent_addr_t)&tv, sizeof(struct timeval));
        if (err < 0) {
            fprintf(stderr, "tracy_write_mem returned %d\n", err);
            tracy_kill_child(e->child);
        }
    }

    return TRACY_HOOK_CONTINUE; 
}

int main(int argc, char** argv) {
    struct tracy *tracy;

    /* Tracy options */
    tracy = tracy_init(TRACY_TRACE_CHILDREN);
#if 0
    tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE |
            TRACY_VERBOSE_SIGNAL | TRACY_VERBOSE_SYSCALL);
#endif

    if (argc != 2) {
        printf("Usage: ./example <program-name|pid>\n");
        return EXIT_FAILURE;
    }

    /* Hooks */
    /*set_hook(stat);*/
    set_hook(open);
    set_hook(time);
    set_hook(clock_gettime);
    set_hook(gettimeofday);

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
