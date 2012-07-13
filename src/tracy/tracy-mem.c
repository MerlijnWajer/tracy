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
 * tracy-mem.c
 *
 * Access to and management of child process memory
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <fcntl.h>

#include <stdio.h>
#include <errno.h>

#include <unistd.h>
#include <sys/syscall.h>

#include "tracy.h"

/* Read a single ``word'' from child e->pid */
int tracy_peek_word(struct tracy_child *child, long from, long *word) {
    errno = 0;

    *word = ptrace(PTRACE_PEEKDATA, child->pid, from, NULL);

    if (errno)
        return -1;

    return 0;
}

/* Read a byte chunk using ptrace's peek/poke API
 * This function is a lot slower than tracy_read_mem which uses the proc
 * filesystem for accessing the child's memory space.
 *
 * If this function errors the 'dest' memory is left in an undefined state.
 *
 * XXX: We currently do not align at word boundaries, furthermore we only read
 * whole words, this might cause trouble on some architectures.
 *
 */
ssize_t tracy_peek_mem(struct tracy_child *c, tracy_parent_addr_t dest,
        tracy_child_addr_t src, ssize_t n) {

    long *l_dest = (long*)dest;

    /* The long source address */
    long from;

    /* Force cast from (void*) to (long) */
    union {
        void *p_addr;
        long l_addr;
    } _cast_addr;

    /* The only way to check for a ptrace peek error is errno, so reset it */
    errno = 0;

    /* Convert source address to a long to be used by ptrace */
    _cast_addr.p_addr = src;
    from = _cast_addr.l_addr;

    /* Peek memory loop */
    while (n > 0) {
        *l_dest = ptrace(PTRACE_PEEKDATA, c->pid, from, NULL);
        if (errno)
            return -1;

        /* Update the various pointers */
        l_dest++;
        from += sizeof(long);
        n -= sizeof(long);
    }

    return from - _cast_addr.l_addr;
}

/* Open child's memory space */
static int open_child_mem(struct tracy_child *c)
{
    char proc_mem_path[18];

    /* Setup memory access via /proc/<pid>/mem */
    sprintf(proc_mem_path, "/proc/%d/mem", c->pid);
    c->mem_fd = open(proc_mem_path, O_RDWR);

    /* If opening failed, we allow us to continue without
     * fast access. We can fall back to other methods instead.
     */
    if (c->mem_fd == -1) {
        perror("tracy: open_child_mem");
        fprintf(stderr, "tracy: Warning: failed to open child memory @ '%s'\n",
            proc_mem_path);
        return -1;
    }

    return 0;
}

/* Returns bytes read */
static ssize_t tracy_ppm_read_mem(struct tracy_child *c,
        tracy_parent_addr_t dest, tracy_child_addr_t src, size_t n) {
    /* Open memory if it's not open yet */
    if (c->mem_fd < 0) {
        if (open_child_mem(c) < 0)
            return -2;
    }

    /* Try seeking this memory postion */
    if (lseek(c->mem_fd, (off_t)src, SEEK_SET) == (off_t)-1)
        return -1;

    errno = 0;

    /* And read. */
    return read(c->mem_fd, dest, n);
}

/* XXX The memory access functions should not be used for reading more than 2GB
 * on 32-bit because they will cause the error handling code to trigger incorrectly
 * while executing successfully
 */
ssize_t tracy_read_mem(struct tracy_child *child,
        tracy_parent_addr_t dest, tracy_child_addr_t src, size_t n) {
    int r;

    if (child->mem_fallback)
        return tracy_peek_mem(child, dest, src, n);

    r = tracy_ppm_read_mem(child, dest, src, n);

    /* The fallback should only trigger upon failure of opening the
     * child's memory, tracy_ppm_read_mem returns -2 when this happens.
     */
    if (r == -2 && (child->tracy->opt & TRACY_MEMORY_FALLBACK)) {
        child->mem_fallback = 1;
        r = tracy_peek_mem(child, dest, src, n);
    }

    return r;
}

int tracy_poke_word(struct tracy_child *child, long to, long word) {
    if (ptrace(PTRACE_POKEDATA, child->pid, to, word)) {
        perror("tracy_poke_word: pokedata");
        return -1;
    }

    return 0;
}

/* Write a byte chunk using ptrace's peek/poke API
 * This function is a lot slower than tracy_write_mem which uses the proc
 * filesystem for accessing the child's memory space.
 *
 * If this function errors the 'dest' child memory is left in an undefined state.
 *
 * XXX: We currently do not align at word boundaries, furthermore we only read
 * whole words, this might cause trouble on some architectures.
 *
 * XXX: We could possibly return the negative of words successfully written
 * on error. When we do, we need to be careful because the negative value
 * returned is used to signal some faults in the tracy_ppm* functions.
 */
ssize_t tracy_poke_mem(struct tracy_child *c, tracy_child_addr_t dest,
        tracy_parent_addr_t src, ssize_t n) {

    long *l_src = (long*)src;

    /* The long target address */
    long to;

    /* Force cast from (void*) to (long) */
    union {
        void *p_addr;
        long l_addr;
    } _cast_addr;

    /* Convert source address to a long to be used by ptrace */
    _cast_addr.p_addr = dest;
    to = _cast_addr.l_addr;

    /* Peek memory loop */
    while (n > 0) {
        if (ptrace(PTRACE_POKEDATA, c->pid, to, *l_src))
            return -1;

        /* Update the various pointers */
        l_src++;
        to += sizeof(long);
        n -= sizeof(long);
    }

    return to - _cast_addr.l_addr;
}


static ssize_t tracy_ppm_write_mem(struct tracy_child *c,
        tracy_child_addr_t dest, tracy_parent_addr_t src, size_t n) {
    /* Open memory if it's not open yet */
    if (c->mem_fd < 0) {
        if (open_child_mem(c) < 0)
            return -2;
    }

    /* Try seeking this memory postion */
    if (lseek(c->mem_fd, (off_t)dest, SEEK_SET) == (off_t)-1)
        return -1;

    errno = 0;

    /* And write. */
    return write(c->mem_fd, src, n);
}

ssize_t tracy_write_mem(struct tracy_child *child,
        tracy_parent_addr_t dest, tracy_child_addr_t src, size_t n) {
    int r;

    if (child->mem_fallback)
        return tracy_poke_mem(child, dest, src, n);

    r = tracy_ppm_write_mem(child, dest, src, n);

    /* The fallback should only trigger upon failure of opening the
     * child's memory, tracy_ppm_write_mem returns -2 when this happens.
     */
    if (r == -2 && (child->tracy->opt & TRACY_MEMORY_FALLBACK)) {
        child->mem_fallback = 1;
        r = tracy_poke_mem(child, dest, src, n);
    }

    return r;
}

/* Execute mmap in the child process */
int tracy_mmap(struct tracy_child *child, tracy_child_addr_t *ret,
        tracy_child_addr_t addr, size_t length, int prot, int flags, int fd,
        off_t pgoffset) {
    struct tracy_sc_args a;

    a.a0 = (long) addr;
    a.a1 = (long) length;
    a.a2 = (long) prot;
    a.a3 = (long) flags;
    a.a4 = (long) fd;
    a.a5 = (long) pgoffset;

    /* XXX: Currently we make no distinction between calling
     * mmap and mmap2 here, however we should add an expression
     * that normalises the offset parameter passed to both flavors of mmap.
     */
    if (tracy_inject_syscall(child, TRACY_NR_MMAP, &a, (long*)ret))
        return -1;

    return 0;
}

/* Execute munmap in the child process */
int tracy_munmap(struct tracy_child *child, long *ret,
       tracy_child_addr_t addr, size_t length) {
    struct tracy_sc_args a;

    a.a0 = (long) addr;
    a.a1 = (long) length;

    if (tracy_inject_syscall(child, __NR_munmap, &a, ret)) {
        return -1;
    }

    return 0;
}

