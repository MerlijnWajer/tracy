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
 * We don't allow the unpacking process to use multithreading as, firstly,
 * it's not required for unzip and/or 7z x, and secondly, it would allow race
 * conditions to occur in our sandbox.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

void *echo(void *arg)
{
    (void) arg;

    printf("self => %p\n", (void *) pthread_self());
    return NULL;
}

int main()
{
    close(open("/tmp/zipjail-input", O_RDONLY));

    pthread_t t1, t2;

    pthread_create(&t1, NULL, &echo, NULL);
    pthread_create(&t2, NULL, &echo, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return 0;
}
