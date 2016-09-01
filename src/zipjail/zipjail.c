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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "tracy.h"
#include "tracyarch.h"

#define PROT_RWX (PROT_READ|PROT_WRITE|PROT_EXEC)
#define MAXPATH 1023

static const char *g_filepath;
static const char *g_dirpath;
static int g_dirpath_length;

static const char *g_syscall_allowed[] = {
    "ioctl", "read", "write", "lseek", "stat", "fstat", "close", "umask",
    "lstat", "exit_group", "fchmod", "utime", "getdents", "chmod", "munmap",
    "rt_sigaction", "brk",
    NULL,
};

static const char *g_openat_allowed[] = {
    "/sys/devices/system/cpu",
    NULL,
};

static const char *_read_path(
    struct tracy_event *e, const char *function, uintptr_t addr)
{
    static char path[MAXPATH+1];

    if(tracy_read_mem(e->child, path, (void *) addr, MAXPATH+1) < 0 ||
            strlen(path) >= MAXPATH+1) {
        fprintf(stderr,
            "Invalid path for %s(2) while in sandbox mode!\n"
            "ip=%p sp=%p abi=%ld\n",
            function, (void *) e->args.ip, (void *) e->args.sp, e->abi
        );
        return NULL;
    }

    return path;
}

static int _sandbox_open(struct tracy_event *e)
{
    char linkpath[MAXPATH+1]; int length; struct stat st;

    const char *filepath = _read_path(e, "open", e->args.a0);
    if(filepath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    // We accept open(..., O_RDONLY).
    if((e->args.a1 & O_ACCMODE) == O_RDONLY) {
        return TRACY_HOOK_CONTINUE;
    }

    if(lstat(filepath, &st) < 0 && errno == ENOENT) {
        return TRACY_HOOK_CONTINUE;
    }

    if(S_ISLNK(st.st_mode) != 0) {
        length = readlink(filepath, linkpath, sizeof(linkpath)-1);
        linkpath[length >= 0 ? length : 0] = 0;

        fprintf(stderr,
            "Detected potential symlink-based arbitrary overwrite!\n"
            "filepath=%s realpath=%s\n", filepath, linkpath
        );
        return TRACY_HOOK_ABORT;
    }

    if(strstr(filepath, "..") != NULL) {
        fprintf(stderr,
            "Detected potential directory traversal arbitrary overwrite!\n"
            "filepath=%s\n", filepath
        );
        return TRACY_HOOK_ABORT;
    }

    if(strcmp(filepath, g_filepath) == 0) {
        return TRACY_HOOK_CONTINUE;
    }

    if(strncmp(filepath, g_dirpath, strlen(g_dirpath)) != 0 ||
            filepath[g_dirpath_length] != '/') {
        fprintf(stderr,
            "Detected potential out-of-path arbitrary overwrite!\n"
            "filepath=%s dirpath=%s\n", filepath, g_dirpath
        );
        return TRACY_HOOK_ABORT;
    }

    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_openat(struct tracy_event *e)
{
    if(e->args.a0 != AT_FDCWD) {
        fprintf(stderr,
            "Invalid dirfd provided for openat(2) while in sandbox mode!\n"
            "ip=%p sp=%p abi=%ld\n",
            (void *) e->args.ip, (void *) e->args.sp, e->abi
        );
        return TRACY_HOOK_ABORT;
    }

    const char *filepath = _read_path(e, "openat", e->args.a1);
    if(filepath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    if(strcmp(filepath, g_dirpath) == 0) {
        return TRACY_HOOK_CONTINUE;
    }

    if(strncmp(filepath, g_dirpath, g_dirpath_length) == 0 &&
            filepath[g_dirpath_length] == '/') {
        return TRACY_HOOK_CONTINUE;
    }

    for (const char **ptr = g_openat_allowed; *ptr != NULL; ptr++) {
        if(strcmp(filepath, *ptr) == 0) {
            return TRACY_HOOK_CONTINUE;
        }
    }

    fprintf(stderr,
        "Trying to openat(2) a path that's not whitelisted: %s!\n",
        filepath
    );
    return TRACY_HOOK_ABORT;
}

static int _sandbox_unlink(struct tracy_event *e)
{
    const char *filepath = _read_path(e, "unlink", e->args.a0);
    if(filepath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_mkdir(struct tracy_event *e)
{
    const char *dirpath = _read_path(e, "mkdir", e->args.a0);
    if(dirpath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    if(strcmp(dirpath, g_dirpath) == 0) {
        return TRACY_HOOK_CONTINUE;
    }

    if(strncmp(dirpath, g_dirpath, g_dirpath_length) == 0 &&
            dirpath[g_dirpath_length] == '/') {
        return TRACY_HOOK_CONTINUE;
    }

    return TRACY_HOOK_ABORT;
}

static int _sandbox_readlink(struct tracy_event *e)
{
    const char *filepath = _read_path(e, "readlink", e->args.a0);
    if(filepath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    if(strcmp(filepath, g_dirpath) == 0) {
        return TRACY_HOOK_CONTINUE;
    }

    if(strncmp(filepath, g_dirpath, g_dirpath_length) == 0 &&
            filepath[g_dirpath_length] == '/') {
        return TRACY_HOOK_CONTINUE;
    }

    return TRACY_HOOK_ABORT;
}

static int _sandbox_mmap(struct tracy_event *e)
{
    fprintf(stderr, "mmap(%lx, %lx, %lx, %lx, %lx, %lx)\n",
        e->args.a0, e->args.a1, e->args.a2, e->args.a3, e->args.a4, e->args.a5
    );

    if((e->args.a2 & PROT_RWX) == PROT_RWX) {
        fprintf(stderr,
            "Blocked mmap(2) syscall with RWX flags set!\n"
        );
        return TRACY_HOOK_ABORT;
    }
    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_mprotect(struct tracy_event *e)
{
    fprintf(stderr, "mprotect(%lx, %lx, %lx)\n",
        e->args.a0, e->args.a1, e->args.a2
    );

    if((e->args.a2 & PROT_RWX) == PROT_RWX) {
        fprintf(stderr,
            "Blocked mprotect(2) syscall with RWX flags set!\n"
        );
        return TRACY_HOOK_ABORT;
    }
    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_allow(struct tracy_event *e)
{
    (void) e;
    return TRACY_HOOK_CONTINUE;
}

static int _zipjail_block(struct tracy_event *e)
{
    const char *syscall = get_syscall_name_abi(e->args.syscall, e->abi);

    fprintf(stderr,
        "Blocked system call occurred during sandboxing!\n"
        "ip=%p sp=%p abi=%ld nr=%ld syscall=%s\n",
        (void *) e->args.ip, (void *) e->args.sp,
        e->abi, e->args.syscall, syscall
    );

    return TRACY_HOOK_ABORT;
}

static int _zipjail_enter_sandbox(struct tracy_event *e)
{
    if(tracy_unset_hook(e->child->tracy, "open", e->abi) < 0) {
        fprintf(stderr, "Error unsetting open trigger hook!\n");
        return TRACY_HOOK_ABORT;
    }

    if(tracy_set_hook(e->child->tracy, "open", e->abi, &_sandbox_open) < 0) {
        fprintf(stderr, "Error setting open(2) sandbox hook!\n");
        return TRACY_HOOK_ABORT;
    }

    if(tracy_set_hook(e->child->tracy, "openat", e->abi,
            &_sandbox_openat) < 0) {
        fprintf(stderr, "Error setting openat(2) sandbox hook!\n");
        return TRACY_HOOK_ABORT;
    }

    if(tracy_set_hook(e->child->tracy, "unlink", e->abi,
            &_sandbox_unlink) < 0) {
        fprintf(stderr, "Error setting unlink(2) sandbox hook!\n");
        return TRACY_HOOK_ABORT;
    }

    if(tracy_set_hook(e->child->tracy, "mkdir", e->abi,
            &_sandbox_mkdir) < 0) {
        fprintf(stderr, "Error setting mkdir(2) sandbox hook!\n");
        return TRACY_HOOK_ABORT;
    }

    if(tracy_set_hook(e->child->tracy, "readlink", e->abi,
            &_sandbox_readlink) < 0) {
        fprintf(stderr, "Error setting readlink(2) sandbox hook!\n");
        return TRACY_HOOK_ABORT;
    }

    if(tracy_set_hook(e->child->tracy, "mmap", e->abi, &_sandbox_mmap) < 0) {
        fprintf(stderr, "Error setting mmap(2) sandbox hook!\n");
        return TRACY_HOOK_ABORT;
    }

    if(tracy_set_hook(e->child->tracy, "mprotect", e->abi,
            &_sandbox_mprotect) < 0) {
        fprintf(stderr, "Error setting mprotect(2) sandbox hook!\n");
        return TRACY_HOOK_ABORT;
    }

    for (const char **sc = g_syscall_allowed; *sc != NULL; sc++) {
        if(tracy_set_hook(e->child->tracy, *sc, e->abi,
                &_sandbox_allow) < 0) {
            fprintf(stderr,
                "Error setting allowed sandbox syscall: %s!\n", *sc
            );
            return TRACY_HOOK_ABORT;
        }
    }

    if(tracy_set_default_hook(e->child->tracy, &_zipjail_block) < 0) {
        fprintf(stderr, "Error setting generic sandbox hook!\n");
        return TRACY_HOOK_ABORT;
    }

    return TRACY_HOOK_CONTINUE;
}

static int _trigger_open(struct tracy_event *e)
{
    char filepath[MAXPATH+1]; int length;

    length = tracy_read_mem(
        e->child, filepath, (void *)(uintptr_t) e->args.a0, sizeof(filepath)-1
    );
    if(length < 0) {
        return TRACY_HOOK_ABORT;
    }

    filepath[length] = 0;

    // Enter sandboxing mode.
    if(strcmp(filepath, g_filepath) == 0) {
        return _zipjail_enter_sandbox(e);
    }

    return TRACY_HOOK_CONTINUE;
}

int main(int argc, char *argv[])
{
    if(argc < 3) {
        fprintf(stderr, "Usage: %s <input> <output> <command...>\n", argv[0]);
        fprintf(stderr, "  input:  input archive file\n");
        fprintf(stderr, "  output: directory to extract files to\n");
        return 1;
    }

    g_filepath = *++argv;
    g_dirpath = *++argv;
    g_dirpath_length = strlen(g_dirpath);

    struct tracy *tracy = tracy_init(0);

    if(tracy_set_hook(tracy, "open", TRACY_ABI_NATIVE, &_trigger_open) < 0) {
        fprintf(stderr, "Error hooking open(2)\n");
        return -1;
    }

    tracy_exec(tracy, ++argv);
    tracy_main(tracy);
    tracy_free(tracy);
    return 0;
}
