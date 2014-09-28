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
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <unistd.h>
#include <sys/syscall.h>

#include "tracy.h"

static ssize_t tracy_peek_mem(struct tracy_child *c, tracy_parent_addr_t dest,
        tracy_child_addr_t src, ssize_t n);
static ssize_t tracy_poke_mem(struct tracy_child *c, tracy_child_addr_t dest,
        tracy_parent_addr_t src, ssize_t n);
static ssize_t tracy_ppm_read_mem(struct tracy_child *c,
        tracy_parent_addr_t dest, tracy_child_addr_t src, size_t n);
static ssize_t tracy_ppm_write_mem(struct tracy_child *c,
        tracy_child_addr_t dest, tracy_parent_addr_t src, size_t n);

/* Read a byte chunk using ptrace's peek/poke API
 * This function is a lot slower than tracy_read_mem which uses the proc
 * filesystem for accessing the child's memory space.
 *
 * If this function errors the 'dest' memory is left in an undefined state.
 */
static ssize_t tracy_peek_mem(struct tracy_child *c, tracy_parent_addr_t dest,
        tracy_child_addr_t src, ssize_t n) {

    char *destbuf = (char*)dest;

    /* The long source address */
    long from, from_outer, from_inner;

    /* Amount of data to read */
    ssize_t data_read = n;

    /* Alignment correction storage */
    union {
        long word;
        char data[sizeof(long)];
    } _landing_zone;

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

    /* Read non-aligned pre word */
    if (n) {
        from_outer = from & ~(sizeof(long) - 1);
        from_inner = from & (sizeof(long) - 1);

        /* Read data */
        _landing_zone.word = ptrace(PTRACE_PEEKDATA, c->pid,
            from_outer, NULL);
        if (errno)
            return -1;

        /* Copy data */
        for (; from_inner < (ssize_t)sizeof(long) && n; n--,
                from_inner++, destbuf++)
            *destbuf = _landing_zone.data[from_inner];
        from_outer += sizeof(long);

        /* Aligned words loop */
        while (n > 0) {
            /* Read data */
            _landing_zone.word = ptrace(PTRACE_PEEKDATA, c->pid,
                from_outer, NULL);
            if (errno)
                return -1;

            /* Copy data */
            for (from_inner = 0; from_inner < (ssize_t)sizeof(long) && n; n--,
                    from_inner++, destbuf++)
                *destbuf = _landing_zone.data[from_inner];
            from_outer += sizeof(long);
        }
    }

    return data_read;
}

/* Open child's memory space */
static int open_child_mem(struct tracy_child *c)
{
    char proc_mem_path[18];

    /* XXX: This method might cause unexpected behaviour
     * or introduce bugs.
     * There must be a safer way to convert the integer
     * to a string.
     */

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
    int res;

    if (c->mem_fd < 0) {
        if (open_child_mem(c) < 0)
            return -2;
    }

    /* Try seeking this memory postion */
    if (lseek(c->mem_fd, (off_t)(uintptr_t)src, SEEK_SET) == (off_t)-1)
        return -1;

    errno = 0;

    /* And read. */
    res = read(c->mem_fd, dest, n);

    close(c->mem_fd);
    c->mem_fd = -1;

    return res;
}

/* Read a string character per character.
   Slow operation but useful when the length of a string is not known */
char* tracy_read_string(struct tracy_child *c,
        tracy_child_addr_t src) {
    char *buf, *curr, *bufwalk;
    int bp, lim;

    bp = 0; /* Buffer pos */
    lim = 4096 * sizeof(char); /* Buffer size */
    curr = src;
    buf = malloc(lim);
    bufwalk = buf; /* We increase this to check the currently read char */

    while (tracy_read_mem(c, bufwalk++, curr++, 1) == 1) {
        if (buf[bp++] == 0)
            break;

        if (bp == (lim-1)) {
            /* XXX Need OOM handling */
            buf = realloc(buf, lim+(4096*sizeof(char)));
            lim += 4096;
        }
    }

    /* XXX On failure of mem read, needs to null terminate string */
    buf = realloc(buf, bp * sizeof(char));
    return buf;
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

/* Write a byte chunk using ptrace's peek/poke API
 * This function is a lot slower than tracy_write_mem which uses the proc
 * filesystem for accessing the child's memory space.
 *
 * If this function errors the 'dest' child memory is left in an undefined state.
 *
 * XXX: We could possibly return the negative of words successfully written
 * on error. When we do, we need to be careful because the negative value
 * returned is used to signal some faults in the tracy_ppm* functions.
 */
static ssize_t tracy_poke_mem(struct tracy_child *c, tracy_child_addr_t dest,
        tracy_parent_addr_t src, ssize_t n) {

    char *srcbuf = (char*)src;

    /* The long destination address */
    long to, to_outer, to_inner;

    /* Amount of data to read */
    ssize_t data_written = n;

    /* Alignment correction storage */
    union {
        long word;
        char data[sizeof(long)];
    } _landing_zone;

    /* Force cast from (void*) to (long) */
    union {
        void *p_addr;
        long l_addr;
    } _cast_addr;

    /* The only way to check for a ptrace poke error is errno, so reset it */
    errno = 0;

    /* Convert destination address to a long to be used by ptrace */
    _cast_addr.p_addr = dest;
    to = _cast_addr.l_addr;

    /* Write non-aligned pre word */
    if (n) {
        to_outer = to & ~(sizeof(long) - 1);
        to_inner = to & (sizeof(long) - 1);

        /* Read data */
        _landing_zone.word = ptrace(PTRACE_PEEKDATA, c->pid,
            to_outer, NULL);
        if (errno)
            return -1;

        /* Modify data */
        for (; to_inner < (ssize_t)sizeof(long) && n; n--,
                to_inner++, srcbuf++)
            _landing_zone.data[to_inner] = *srcbuf;

        /* Write back modified word */
        ptrace(PTRACE_POKEDATA, c->pid, to_outer, _landing_zone.word);
        if (errno)
            return -1;
        to_outer += sizeof(long);

        /* Aligned words loop */
        while (n >= (ssize_t)sizeof(long)) {
            /* Copy data */
            for (to_inner = 0; to_inner < (ssize_t)sizeof(long) && n; n--,
                    to_inner++, srcbuf++)
                _landing_zone.data[to_inner] = *srcbuf;

            /* Write data */
            ptrace(PTRACE_POKEDATA, c->pid, to_outer, _landing_zone.word);

            if (errno)
                return -1;
            to_outer += sizeof(long);
        }

        /* Finally write last misaligned data, if any. */
        if (n) {
            /* Read data */
            _landing_zone.word = ptrace(PTRACE_PEEKDATA, c->pid,
                to_outer, NULL);
            if (errno)
                return -1;

            /* Modify data */
            for (to_inner = 0; n; n--, to_inner++, srcbuf++)
                _landing_zone.data[to_inner] = *srcbuf;

            /* Write back modified word */
            ptrace(PTRACE_POKEDATA, c->pid, to_outer, _landing_zone.word);
            if (errno)
                return -1;
            to_outer += sizeof(long);
        }
    }

    return data_written;
}


static ssize_t tracy_ppm_write_mem(struct tracy_child *c,
        tracy_child_addr_t dest, tracy_parent_addr_t src, size_t n) {
    int res;

    /* Open memory if it's not open yet */
    if (c->mem_fd < 0) {
        if (open_child_mem(c) < 0)
            return -2;
    }

    /* Try seeking this memory postion */
    if (lseek(c->mem_fd, (off_t)(uintptr_t)dest, SEEK_SET) == (off_t)-1)
        return -1;

    errno = 0;

    /* And write. */
    res = write(c->mem_fd, src, n);

    close(c->mem_fd);
    c->mem_fd = -1;

    return res;
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
    long mmap_nr;

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
#pragma message "mmap2?"
    mmap_nr = get_syscall_number_abi("mmap2", child->event.abi);
    if (mmap_nr == -1)
        mmap_nr = get_syscall_number_abi("mmap", child->event.abi);
    if (tracy_inject_syscall(child, mmap_nr, &a, (long*)ret))
        return -1;

    return 0;
}

/* Execute munmap in the child process */
int tracy_munmap(struct tracy_child *child, long *ret,
       tracy_child_addr_t addr, size_t length) {
    struct tracy_sc_args a;
    long munmap_nr;

    a.a0 = (long) addr;
    a.a1 = (long) length;

    munmap_nr = get_syscall_number_abi("munmap", child->event.abi);
    if (tracy_inject_syscall(child, munmap_nr, &a, ret)) {
        return -1;
    }

    return 0;
}

