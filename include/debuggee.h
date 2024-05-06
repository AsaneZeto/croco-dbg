#ifndef DEBUGEE_H
#define DEBUGEE_H

#include <stdint.h>
#include "breakpoint.h"
#include "hashtbl.h"

typedef struct {
    hashtbl_t *hashtbl;
    breakpoint_t bp[MAX_BP];
    size_t nBp;
} debuggee_t;

void dbe_init(debuggee_t *dbe);
void dbe_start(const char *prog);
void dbe_close(debuggee_t *dbe);
bool dbe_set_bp(debuggee_t *dbe, uintptr_t *addr_p);
void dbe_dump_bp(debuggee_t *dbe);
size_t dbe_read_mem(debuggee_t *dbe, uintptr_t addr);
bool dbe_write_mem(debuggee_t *dbe, uintptr_t addr, size_t value);

#endif 