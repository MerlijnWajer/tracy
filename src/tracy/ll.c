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
#include <stdlib.h>

#include "ll.h"

struct soxy_ll* ll_init(void) {
    struct soxy_ll* ll = malloc(sizeof(struct soxy_ll));
    ll->head = NULL;

    return ll;
}

int ll_free(struct soxy_ll* ll) {
    if(ll->head)
        while (ll->head->next) {
            ll_del(ll, ll->head->next->id);
        }

    if (ll->head) {
        ll_del(ll, ll->head->id);
    }

    return 0;
}

int ll_add(struct soxy_ll* ll, int id, void* d) {
    struct soxy_ll_item *t, *tt;

    t = ll_find(ll, id);
    if (t)
        return -1;

    t = malloc(sizeof(struct soxy_ll_item));
    t->data = d;
    t->id = id;
    t->prev = NULL;
    t->next = NULL;

    if (!ll->head) {
        ll->head = t;
    } else {
        tt = ll->head;

        while(tt->next) {
            tt = tt->next;
        }

        tt->next = t;
        t->prev = tt;
    }

    return 0;
}

int ll_del(struct soxy_ll* ll, int id) {
    struct soxy_ll_item *t = ll_find(ll, id);

    if(t) {
        if (t->prev)
            t->prev->next = t->next;
        if (t->next)
            t->next->prev = t->prev;

        if (ll->head == t) {
            if (t->next) {
                ll->head = t->next;
            } else {
                ll->head = NULL;
                free(t);
                return 0;
            }
        }

        free(t);
        return 0;
    }

    return -1;
}

struct soxy_ll_item* ll_find(struct soxy_ll* ll, int id) {
    struct soxy_ll_item *t;

    t = ll->head;

     while (t) {
        if (t->id == id)
            return t;
        t = t->next;
     }

    return NULL;
}
