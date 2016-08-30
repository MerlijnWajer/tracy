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

/* Mmap stuffs */
#include <sys/mman.h>

static int child__llseek(struct tracy_child *child, int fd, unsigned long  offset_hi, unsigned long  offset_lo, loff_t*  result, int  whence) {
    struct tracy_sc_args a;
    long llseek_nr;
    long ret;

    fprintf(stderr, "%s(%u, %lu, %lu, %p, %u)\n", __func__, fd, offset_hi, offset_lo, (void*)result, whence);

    a.a0 = (long) fd;
    a.a1 = (long) offset_hi;
    a.a2 = (long) offset_lo;
    a.a3 = (long) NULL;
    a.a3 = (long) result;
    a.a4 = (long) whence;

    /* DEBUG LOL */
    a.a5 = (long) 0x42;

    printf("Should be: %lx %lx %lx %lx %lx %lx\n", a.a0, a.a1, a.a2, a.a3, a.a4, a.a5);

    llseek_nr = get_syscall_number_abi("_llseek", child->event.abi);
    if (tracy_inject_syscall(child, llseek_nr, &a, &ret)) {
        fprintf(stderr, "Injection error!\n");
        return -1;
    }

    return ret;
}

loff_t child_lseek64(struct tracy_child *child, int fd, off64_t off, int whence)
{
    loff_t  result;
    int rc;
    int ret;

    tracy_child_addr_t mmap_ret = NULL;
    long munmap_ret = 0;

    ret = tracy_mmap(child, &mmap_ret, NULL, 4096, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    printf("Tracy ret: %d\n", ret);
    printf("Tracy ptr: %lx\n", (unsigned long)mmap_ret);

    if ((rc=child__llseek(child, fd, (unsigned long)(off >> 32),(unsigned long)(off), (loff_t*)mmap_ret, whence)) < 0 ){
    /*if ((rc=child__llseek(child, fd, (unsigned long)(off >> 32),(unsigned long)(off), &result, whence)) < 0 ){*/
        fprintf(stderr, "llseek64_error: %d\n", rc);
        return -1;
    }

    ret = tracy_read_mem(child, &result, mmap_ret, sizeof(loff_t));
    /* XXX: Check return value of iets dergelijks */
    printf("tracy_read_mem ret: %d\n", ret);

    ret = tracy_munmap(child, &munmap_ret, mmap_ret, 4096);
    printf("tracy_munmap ret: %d\n", ret);


    return result;
}

int hook_open(struct tracy_event *e) {
    loff_t rc;

    if (e->child->pre_syscall) {
        /*printf("open()\n");*/
    } else {
        int fd = e->args.return_code;
        if(fd<=2) {
            goto cont;
        }

        printf("fd=%d\n", fd);
        rc = child_lseek64(e->child, fd, 0x100, SEEK_CUR);
        printf("rc=%lld\n", (long long int) rc);

        return TRACY_HOOK_CONTINUE;
        /*return TRACY_HOOK_ABORT;*/
    }

cont:
    return TRACY_HOOK_CONTINUE;
}

int main(int argc, char** argv) {
    struct tracy *tracy;

    /* Tracy options */
    tracy = tracy_init(TRACY_TRACE_CHILDREN);

    if (tracy_set_hook(tracy, "open", TRACY_ABI_NATIVE, hook_open)) {
        fprintf(stderr, "Could not hook open\n");
        return EXIT_FAILURE;
    }

    if (argc < 2) {
        printf("Usage: ./example <program-name>\n");
        return EXIT_FAILURE;
    }

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
