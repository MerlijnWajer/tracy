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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ll.h"

int main() {
    struct soxy_ll *l;
    struct soxy_ll_item *t;
    char *s, *s2, *s3;

    s = malloc(sizeof(char) * 10);
    s2 = malloc(sizeof(char) * 10);
    s3 = malloc(sizeof(char) * 10);

    l = ll_init();

    strcpy(s, "hello");
    strcpy(s2, "world");
    strcpy(s3, "forty-two");
    ll_add(l, 0, s);
    ll_add(l, 1, s2);
    ll_add(l, 2, s3);
    printf("Inserting clone results: %d\n", ll_add(l, 2, s3));

    t = ll_find(l, 0);
    printf("LL(0) says %s\n", (char*)t->data);
    printf("LL(0)->next says %s\n", (char*)t->next->data);
    printf("LL(0)->next->next says %s\n", (char*)t->next->next->data);
    printf("LL(0)->next->next->prev->prev says %s\n", (char*)t->next->next->prev->prev->data);


    ll_del(l, 0);
    printf("Deleting 0\n");

    ll_del(l, 2);
    ll_del(l, 1);
    ll_del(l, 3);

    t = ll_find(l, 1);
    if (t)
        printf("LL(1) says %s\n", (char*)t->data);


    ll_free(l);

    return 0;

}
