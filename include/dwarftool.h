#pragma once

#include <libdwarf/libdwarf.h>

#include "list.h"

typedef struct {
    int fd;
    Dwarf_Debug dbg;
    Dwarf_Error error;
    Dwarf_Handler errhand;
    Dwarf_Ptr errarg;
    Dwarf_Arange *all_aranges;
    Dwarf_Signed n_aranges;
    size_t n_cus;
    struct list_head cus;
} dw_context_t;

typedef struct {
    Dwarf_Off off;
    Dwarf_Line *lines;
    Dwarf_Signed n_lines;
    struct list_head list;
} dw_cu_t;

int dw_init(dw_context_t *dw_ctx, const char *prog);
int dw_finish(dw_context_t *dw_ctx);

void dw_print_source(dw_context_t *dw_ctx, uintptr_t addr);

/* Get the function DIE of the symbol */
bool dw_get_func_die_by_symbol(dw_context_t *dw_ctx,
                               Dwarf_Die *ret_die,
                               const char *symbol);
/* Get the function DIE where the address is */
bool dw_get_func_die_by_addr(dw_context_t *dw_ctx,
                             Dwarf_Die *ret_die,
                             uintptr_t addr);

/* Get source file line of an address */
bool dw_get_line_by_addr(dw_context_t *dw_ctx,
                         Dwarf_Line *ret_line,
                         uintptr_t addr);

/* Get address of a function symbol */
bool dw_get_addr_by_func_sym(dw_context_t *dw_ctx,
                          const char *func_name,
                          uintptr_t *addr);


bool dw_get_addr_by_srcline(dw_context_t *dw_ctx,
                             const char *srcline,
                             uintptr_t *addr);

bool dw_get_addr_by_line(dw_context_t *dw_ctx,
                         int line,
                         uintptr_t *addr);
