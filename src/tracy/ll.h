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
#ifndef LL_H
#define LL_H

struct soxy_ll_item {
    void* data;
    int id;
    struct soxy_ll_item* prev;
    struct soxy_ll_item* next;
};

struct soxy_ll {
    struct soxy_ll_item *head;
};

struct soxy_ll* ll_init(void);
int ll_free(struct soxy_ll* ll);

int ll_add(struct soxy_ll* ll, int id, void* d);
int ll_del(struct soxy_ll* ll, int id);
struct soxy_ll_item *ll_find(struct soxy_ll* ll, int id);

#endif
