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
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main () {
    pid_t pid;
    int foo;
    printf("f: Hello\n");

    /* pid = fork(); */
    puts("Executing fork() in a safe environment now");
    pid = syscall(__NR_fork);
    puts("Done with fork in a safe environment... we're free of the endless loop.");

    if (!pid) {
        printf("f: You should not yet see this\n");
    } else {
        /* sleep(5); */
        printf("f: See this first\n");
        wait(&foo);
        printf("f: Child is dead\n");
    }

    printf("f: Done\n");

    return 0;
}

