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
