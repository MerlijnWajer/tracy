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
