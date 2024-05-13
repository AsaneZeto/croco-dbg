#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>

#include "debuggee.h"
#include "debugger.h"
#include "dwarftool.h"
#include "tools.h"

void dbe_init(debuggee_t *dbe)
{
    dbe->hashtbl = calloc(1, sizeof(hashtbl_t));
    hashtbl_create(MAX_BP, dbe->hashtbl);
    dbe->nBp = 0;
}

bool dbe_set_bp(debuggee_t *dbe, uintptr_t *addr_p)
{
    if (dbe->nBp + 1 > MAX_BP) {
        fprintf(stderr, "ERROR: The number of breakpoints reach max limit\n");
        return false;
    }

    bp_init(&dbe->bp[dbe->nBp], container_of(dbe, debugger_t, dbe)->pid,
            *addr_p);
    bp_enable(&dbe->bp[dbe->nBp]);

    if (!hashtbl_add(dbe->hashtbl, dbe->bp[dbe->nBp].addr_key,
                     (void *) &dbe->nBp)) {
        fprintf(stderr, "ERROR: record breakpoint failed\n");
        return false;
    }

    dbe->nBp++;

    fprintf(stdout, "Set breakpoint at address 0x%lx\n", *addr_p);
    return true;
}

bool dbe_set_bp_symbol(debuggee_t *dbe, char *symbol)
{
    if (dbe->nBp + 1 > MAX_BP) {
        fprintf(stderr, "ERROR: The number of breakpoints reach max limit\n");
        return false;
    }

    uintptr_t addr = 0;
    if (!dw_get_func_sym_addr(&container_of(dbe, debugger_t, dbe)->dw_ctx,
                              symbol, &addr)) {
        fprintf(stderr, "ERROR: Cannot find the address of %s\n", symbol);
        return false;
    }

    addr = container_of(dbe, debugger_t, dbe)->load_addr + addr;

    bp_init(&dbe->bp[dbe->nBp], container_of(dbe, debugger_t, dbe)->pid, addr);
    bp_enable(&dbe->bp[dbe->nBp]);

    if (!hashtbl_add(dbe->hashtbl, dbe->bp[dbe->nBp].addr_key,
                     (void *) &dbe->nBp)) {
        fprintf(stderr, "ERROR: record breakpoint failed\n");
        return false;
    }

    dbe->nBp++;

    fprintf(stdout, "Set breakpoint at %s() (0x%lx)\n", symbol, addr);
    return true;
}

void dbe_dump_bp(debuggee_t *dbe)
{
    if (!dbe)
        return;

    if (dbe->nBp == 0) {
        fprintf(stderr, "No breakpoint exists\n");
        return;
    }

    size_t *data = NULL;
    for (size_t i = 0; i < dbe->nBp; i++) {
        hashtbl_search(dbe->hashtbl, dbe->bp[i].addr_key, (void **) &data);
        fprintf(stdout, "Breakpoints %ld: 0x%s\n", *data - 1,
                dbe->bp[i].addr_key);
    }
}

size_t dbe_read_mem(debuggee_t *dbe, uintptr_t addr)
{
    return ptrace(PTRACE_PEEKDATA, container_of(dbe, debugger_t, dbe)->pid,
                  (void *) addr, NULL);
}

bool dbe_write_mem(debuggee_t *dbe, uintptr_t addr, size_t value)
{
    int ret = ptrace(PTRACE_POKEDATA, container_of(dbe, debugger_t, dbe)->pid,
                     (void *) addr, value);

    if (ret == -1) {
        fprintf(stderr, "ERROR: write to memory.\n");
        return false;
    }

    return true;
}

void dbe_close(debuggee_t *dbe)
{
    hashtbl_destroy(dbe->hashtbl);
}