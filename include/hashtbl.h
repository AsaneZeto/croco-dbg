#ifndef HASHTBL_H
#define HASHTBL_H

#include <search.h>
#include <stdbool.h>

typedef struct {
    struct hsearch_data htab; 
    size_t size;
} hashtbl_t;

bool hashtbl_create(size_t size, hashtbl_t *hashtbl);
bool hashtbl_add(hashtbl_t *hashtbl, char *key, void *data);
bool hashtbl_search(hashtbl_t *hashtbl, char *key, void **data);
void hashtbl_destroy(hashtbl_t *hashtbl);

#endif