#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <dwarf.h>
#include "dwarftool.h"

int dw_init(dw_context_t *dw_ctx, const char *prog)
{   
    int fd = -1;
    fd = open(prog, O_RDONLY);
    if(fd == -1)
        return -1;

    dw_ctx->fd = fd;

    /* Start initializing DWARF information */
    if(dwarf_init(fd, DW_DLC_READ, dw_ctx->errhand, dw_ctx->errarg, 
                    &dw_ctx->dbg, &dw_ctx->error) != DW_DLV_OK) {
		fprintf(stderr, "Giving up, cannot do DWARF processing\n");
		return -1;
	}

    if (dwarf_get_aranges(dw_ctx->dbg, &dw_ctx->all_aranges, 
        &dw_ctx->n_aranges, &dw_ctx->error) != DW_DLV_OK) {
        fprintf(stderr, "dwarf_get_aranges failed\n");
        return -1;
    }

    /* Only add when first retrieving a compilation units */ 
    INIT_LIST_HEAD(&dw_ctx->cus);

    return 0;
}

int dw_finish(dw_context_t *dw_ctx)
{   
    dw_cu_t *ptr, *safe;
    list_for_each_entry_safe(ptr, safe, &dw_ctx->cus, list) {
        dwarf_srclines_dealloc(dw_ctx->dbg, ptr->lines, ptr->n_lines);
        list_del(&ptr->list);
        free(ptr);
    }

    dwarf_dealloc(dw_ctx->dbg, dw_ctx->all_aranges, DW_DLA_LIST);

    if(dwarf_finish(dw_ctx->dbg, &dw_ctx->error) != DW_DLV_OK) {
		fprintf(stderr, "dwarf_finish failed!\n");
        return -1;
	}

	close(dw_ctx->fd);
    return 0;
}


static void 
_find_cu_by_addr(dw_context_t *dw_ctx, dw_cu_t **ret_node, uintptr_t addr)
{

    Dwarf_Arange arange;
    if (dwarf_get_arange(dw_ctx->all_aranges, dw_ctx->n_aranges, addr,
        &arange, &dw_ctx->error) != DW_DLV_OK) {
		fprintf(stderr, "get_arange failed\n");
		return;
	}

    Dwarf_Off off = 0;
    if (dwarf_get_cu_die_offset(arange, &off, &dw_ctx->error) != DW_DLV_OK) {
		fprintf(stderr, "get_cu_die_offset failed\n");
		return;
	}

    /* Check if already retrieved this CU */
    dw_cu_t *ptr;
    list_for_each_entry(ptr, &dw_ctx->cus, list) {
        if(ptr->off == off) {
            *ret_node = ptr;
            return;
        }
    }

    /* First need this CU  */
    Dwarf_Die cu_die;
    if(dwarf_offdie(dw_ctx->dbg, off, &cu_die, &dw_ctx->error) != DW_DLV_OK) {
        fprintf(stderr, "get_cu_die_offset failed\n");
        return;
    };

    Dwarf_Line *lines = NULL;
    Dwarf_Signed n_lines = 0;
    if (dwarf_srclines(cu_die, &lines, &n_lines, &dw_ctx->error) != DW_DLV_OK) {
        fprintf(stderr, "dwarf_srclines failed\n");
        return;
    }

    dwarf_dealloc(dw_ctx->dbg, cu_die, DW_DLA_DIE);

    dw_cu_t *cu_node = (dw_cu_t *) malloc(sizeof(dw_cu_t));
    if(!cu_node) {
        fprintf(stderr, "Create CU node failed\n");
        return;
    }
    
    cu_node->off = off;
    cu_node->lines = lines;
    cu_node->n_lines = n_lines;
    INIT_LIST_HEAD(&cu_node->list);
    list_add_tail(&cu_node->list, &dw_ctx->cus);
    *ret_node = cu_node;
    return;
}

static void
_find_func_die_by_addr(dw_context_t *dw_ctx, Dwarf_Die cu_die,
                       Dwarf_Die *ret_die, uintptr_t addr)
{   

	Dwarf_Die cur_die = cu_die;
	Dwarf_Die sib_die = cu_die;
	Dwarf_Die child = NULL;

    Dwarf_Half tag;
    const char *tag_name = NULL;
    int got_tag_name = !dwarf_tag(cur_die, &tag, &dw_ctx->error) && 
                       !dwarf_get_TAG_name(tag, &tag_name);
    if(got_tag_name && strcmp(tag_name, "DW_TAG_subprogram") == 0) {
        Dwarf_Addr lowpc, highpc;
        /* dwarf_highpc_b works for DWARF4 style DW_AT_highpc */
        int ret_pc = !dwarf_lowpc(cur_die, &lowpc, &dw_ctx->error) && 
                     !dwarf_highpc_b(cur_die, &highpc, NULL, NULL, &dw_ctx->error);
        
        if(ret_pc && lowpc <= addr && addr <= (lowpc + highpc)) {
            /* Find target DIE */
            *ret_die = cur_die;
            return;
        }
    }

	/* First son, if any */
	int ret = dwarf_child(cur_die, &child, &dw_ctx->error);
    /* traverse tree depth first */
	if(ret == DW_DLV_OK)
	{   
        _find_func_die_by_addr(dw_ctx, child, ret_die, addr); /* recur on the first son */
		sib_die = child;
		while(ret == DW_DLV_OK) {
            cur_die = sib_die;
			ret = dwarf_siblingof(dw_ctx->dbg, cur_die, &sib_die, &dw_ctx->error);
			_find_func_die_by_addr(dw_ctx, sib_die, ret_die, addr); /* recur others */
		};
	}

	return;
}

void dw_get_func_die_by_addr(dw_context_t *dw_ctx, Dwarf_Die *ret_die, uintptr_t addr)
{
    dw_cu_t *cu = NULL;
    _find_cu_by_addr(dw_ctx, &cu, addr);

    if(!cu) {
        fprintf(stderr, "Get CU failed\n");
        return;
    }

    Dwarf_Die cu_die = 0;
    if (dwarf_offdie(dw_ctx->dbg, cu->off, &cu_die, &dw_ctx->error) != DW_DLV_OK) {
		fprintf(stderr, "off_die failed\n");
		return;
	}
    _find_func_die_by_addr(dw_ctx, cu_die, ret_die, addr);

    dwarf_dealloc(dw_ctx->dbg, cu_die, DW_DLA_DIE);
}

void dw_get_line_by_addr(dw_context_t *dw_ctx, Dwarf_Line *ret_line, uintptr_t addr)
{
    dw_cu_t *cu = NULL;
    _find_cu_by_addr(dw_ctx, &cu, addr);

    if(!cu) {
        fprintf(stderr, "Get CU failed\n");
        return;
    }

    Dwarf_Addr line_addr_cur = 0, line_addr_nxt = 0;
    for(Dwarf_Signed i = 0; i < cu->n_lines - 1; i++) {
        dwarf_lineaddr(cu->lines[i], &line_addr_cur, &dw_ctx->error);
        dwarf_lineaddr(cu->lines[i+1], &line_addr_nxt, &dw_ctx->error);
        if(line_addr_cur <= addr && addr < line_addr_nxt) {
            *ret_line = cu->lines[i];
            return;
        }
    }
}