/*
    This file is part of Tracy.

    Foobar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Foobar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
*/
#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

int foo() {
    void *child_addr;

    child_addr = mmap(NULL, sysconf(_SC_PAGESIZE),
             PROT_READ, MAP_PRIVATE | MAP_ANON,
             -1, 0
             );

    printf("CHILD MMAP LOLOL: %p\n", child_addr);

    return 0;
}
int main() {
    foo();

    return 0;
}
