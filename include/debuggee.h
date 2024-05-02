#ifndef DEBUGEE_H
#define DEBUGEE_H

#include "breakpoint.h"
#include "hashtbl.h"

typedef struct {
    hashtbl_t *hashtbl;
    breakpoint_t bp[MAX_BP];
    size_t nBp;
} debuggee_t;

void dbe_init(debuggee_t *dbe);
void dbe_start(const char *prog);
bool dbe_set_bp(debuggee_t *dbe, uintptr_t *addr_p);
void dbe_dump_bp(debuggee_t *dbe);

#endif 