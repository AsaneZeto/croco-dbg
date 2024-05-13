#include "hashtbl.h"

bool hashtbl_create(size_t size, hashtbl_t *hashtbl)
{
    int n = hcreate_r(size, &hashtbl->htab);

    if (n == 0)
        return false;

    hashtbl->size = size;
    return true;
}

bool hashtbl_add(hashtbl_t *hashtbl, char *key, void *data)
{
    ENTRY e;
    ENTRY *ep;

    e.key = key;
    e.data = data;
    int n = hsearch_r(e, ENTER, &ep, &hashtbl->htab);

    if (n == 0)
        return false;

    return true;
}

bool hashtbl_search(hashtbl_t *hashtbl, char *key, void **data)
{
    ENTRY e;
    ENTRY *ep;

    e.key = key;
    e.data = data;
    int n = hsearch_r(e, FIND, &ep, &hashtbl->htab);

    if (n == 0)
        return false;

    *data = ep->data;
    return true;
}

void hashtbl_destroy(hashtbl_t *hashtbl)
{
    hdestroy_r(&hashtbl->htab);
}