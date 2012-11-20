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
/* Dotty.
 *
 * Generate .dot files from system calls made by processes.
 *
 * Dotty is: very incomplete, has quite as few bugs, doesn't trace fork(2) and
 * vfork(2), at least not in the graph, and the .dot output becomes quite
 * useless after the .dot file grows to extreme proportions.
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

FILE* dot;

int foo(struct tracy_event *e) {
    long count;

    if (!e->child->pre_syscall) {
        printf("clone: %ld\n", e->args.return_code);
        e->child->custom = (void*) ((long)e->child->custom + 1);
        count = (long) e->child->custom;
        fprintf(dot, "pid_%d_%ld [label=\"%s\"]\n", e->child->pid, count - 1, get_syscall_name(e->syscall_num));
        fprintf(dot, "pid_%d_%ld -> pid_%d_%ld\n", e->child->pid, count - 1, e->child->pid, count);
        fprintf(dot, "pid_%d_%ld -> pid_%ld_%ld\n", e->child->pid, count, e->args.return_code, 0l);

    } else {
        e->child->custom = (void*) ((long)e->child->custom + 1);
        count = (long) e->child->custom;
        fprintf(dot, "pid_%d_%ld [label=\"%s\"]\n", e->child->pid, count - 1, get_syscall_name(e->syscall_num));
        fprintf(dot, "pid_%d_%ld -> pid_%d_%ld\n", e->child->pid, count - 1, e->child->pid, count);
    }

    return 0;
}

int all(struct tracy_event *e) {
    long count;

    e->child->custom = (void*) ((long)e->child->custom + 1);
    count = (long) e->child->custom;
    if (count == 1) {
        fprintf(dot, "pid_%d_%ld\n", e->child->pid, count - 1);
        fprintf(dot, "pid_%d_%ld -> pid_%d_%ld\n", e->child->pid, count - 1, e->child->pid, count);
    }
    fprintf(dot, "pid_%d_%ld [label=\"%s\"]\n", e->child->pid, count - 1, get_syscall_name(e->syscall_num));
    fprintf(dot, "pid_%d_%ld -> pid_%d_%ld\n", e->child->pid, count - 1, e->child->pid, count);

    return 0;
}

int main(int argc, char** argv) {
    struct tracy *tracy;

    tracy = tracy_init(TRACY_TRACE_CHILDREN);

    if (argc < 2) {
        printf("Usage: dotty <program name> <program arguments>\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "clone", foo)) {
        printf("Failed to hook write syscall.\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_default_hook(tracy, all)) {
        printf("Failed to hook default hook.\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;
    if (!tracy_exec(tracy, argv)) {
        perror("tracy_exec returned NULL");
        return EXIT_FAILURE;
    }

    dot = fopen("out.dot", "w+");
    fprintf(dot, "digraph generated {\n");

    tracy_main(tracy);

    tracy_free(tracy);

    fprintf(dot, "}\n");
    fclose(dot);

    return 0;
}
