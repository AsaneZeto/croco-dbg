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