#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dwarf.h>
#include "dwarftool.h"

#define MAX_BUFFER 1024

static bool _dw_add_cu_node(dw_context_t *dw_ctx, Dwarf_Die *cu_die)
{
    /* Get section-relative offset of CU die */
    Dwarf_Off off = 0;
    if (dwarf_dieoffset(*cu_die, &off, &dw_ctx->error) != DW_DLV_OK) {
        fprintf(stderr, "ERROR: get_cu_die_offset failed\n");
        return false;
    };
    Dwarf_Line *lines = NULL;
    Dwarf_Signed n_lines = 0;
    if (dwarf_srclines(*cu_die, &lines, &n_lines, &dw_ctx->error) !=
        DW_DLV_OK) {
        fprintf(stderr, "ERROR: dwarf_srclines failed\n");
        return false;
    }

    dw_cu_t *cu_node = (dw_cu_t *) malloc(sizeof(dw_cu_t));
    if (!cu_node) {
        fprintf(stderr, "ERROR: Create CU node failed\n");
        return false;
    }

    cu_node->off = off;
    cu_node->lines = lines;
    cu_node->n_lines = n_lines;
    INIT_LIST_HEAD(&cu_node->list);
    list_add_tail(&cu_node->list, &dw_ctx->cus);

    return true;
}

static bool _dw_load_cu(dw_context_t *dw_ctx)
{
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Half version_stamp = 0;
    Dwarf_Unsigned abbrev_offset = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Unsigned next_cu_header = 0;
    dw_ctx->n_cus = 0;
    for (;; dw_ctx->n_cus++) {
        Dwarf_Die no_die = 0;
        Dwarf_Die cu_die = 0;
        int ret = dwarf_next_cu_header(
            dw_ctx->dbg, &cu_header_length, &version_stamp, &abbrev_offset,
            &address_size, &next_cu_header, &dw_ctx->error);
        if (ret == DW_DLV_ERROR)
            return false;
        if (ret == DW_DLV_NO_ENTRY)
            return true;

        /* The CU will have a single sibling, a cu_die. */
        ret = dwarf_siblingof(dw_ctx->dbg, no_die, &cu_die, &dw_ctx->error);
        if (ret == DW_DLV_ERROR)
            return false;
        if (ret == DW_DLV_NO_ENTRY)
            return true;

        _dw_add_cu_node(dw_ctx, &cu_die);
        dwarf_dealloc(dw_ctx->dbg, cu_die, DW_DLA_DIE);
    }

    return true;
}

static bool _find_cu_by_addr(dw_context_t *dw_ctx,
                             dw_cu_t **ret_node,
                             uintptr_t addr)
{
    Dwarf_Arange arange;
    if (dwarf_get_arange(dw_ctx->all_aranges, dw_ctx->n_aranges, addr, &arange,
                         &dw_ctx->error) != DW_DLV_OK) {
        fprintf(stderr, "ERROR: get_arange failed\n");
        return false;
    }

    Dwarf_Off off = 0;
    if (dwarf_get_cu_die_offset(arange, &off, &dw_ctx->error) != DW_DLV_OK) {
        fprintf(stderr, "ERROR: get_cu_die_offset failed\n");
        return false;
    }

    /* Find corresponding CU node */
    dw_cu_t *ptr;
    list_for_each_entry(ptr, &dw_ctx->cus, list)
    {
        if (ptr->off == off) {
            *ret_node = ptr;
            return false;
        }
    }

    return true;
}

/* FIXME: Refine duplciated code */
static bool _find_func_die_by_addr(dw_context_t *dw_ctx,
                                   Dwarf_Die cu_die,
                                   Dwarf_Die *ret_die,
                                   uintptr_t addr)
{
    Dwarf_Die cur_die = cu_die;
    Dwarf_Die sib_die = cu_die;
    Dwarf_Die child = NULL;

    Dwarf_Half tag;
    const char *tag_name = NULL;
    int got_tag_name = !dwarf_tag(cur_die, &tag, &dw_ctx->error) &&
                       !dwarf_get_TAG_name(tag, &tag_name);
    if (got_tag_name && tag == DW_TAG_subprogram) {
        Dwarf_Addr lowpc, highpc;
        /* dwarf_highpc_b works for DWARF4 style DW_AT_highpc */
        int ret_pc =
            !dwarf_lowpc(cur_die, &lowpc, &dw_ctx->error) &&
            !dwarf_highpc_b(cur_die, &highpc, NULL, NULL, &dw_ctx->error);

        if (ret_pc && lowpc <= addr && addr <= (lowpc + highpc)) {
            /* Found target DIE */
            *ret_die = cur_die;
            return true;
        }
    }

    /* First son, if any */
    int ret = dwarf_child(cur_die, &child, &dw_ctx->error);
    bool found = false;
    /* traverse tree depth first */
    if (ret == DW_DLV_OK && !found) {
        _find_func_die_by_addr(dw_ctx, child, ret_die,
                               addr); /* recur on the first son */
        sib_die = child;
        while (ret == DW_DLV_OK) {
            cur_die = sib_die;
            ret =
                dwarf_siblingof(dw_ctx->dbg, cur_die, &sib_die, &dw_ctx->error);
            found = _find_func_die_by_addr(dw_ctx, sib_die, ret_die,
                                           addr); /* recur others */
        };
    }

    return false;
}

static bool _find_func_die_by_symbol(dw_context_t *dw_ctx,
                                     Dwarf_Die die,
                                     Dwarf_Die *ret_die,
                                     const char *symbol)
{
    Dwarf_Die cur_die = die;
    Dwarf_Die sib_die = die;
    Dwarf_Die child = NULL;

    Dwarf_Half tag;
    const char *tag_name = NULL;
    int got_tag_name = !dwarf_tag(cur_die, &tag, &dw_ctx->error) &&
                       !dwarf_get_TAG_name(tag, &tag_name);
    if (got_tag_name && tag == DW_TAG_subprogram) {
        char *name = NULL;
        dwarf_diename(die, &name, &dw_ctx->error);
        if (name != NULL && strcmp(name, symbol) == 0) {
            *ret_die = cur_die;
            return true;
        }
    }

    /* First son, if any */
    int ret = dwarf_child(cur_die, &child, &dw_ctx->error);
    bool found = false;
    /* traverse tree depth first */
    if (ret == DW_DLV_OK) {
        _find_func_die_by_symbol(dw_ctx, child, ret_die,
                                 symbol); /* recur on the first son */
        sib_die = child;
        while (ret == DW_DLV_OK && !found) {
            cur_die = sib_die;
            ret =
                dwarf_siblingof(dw_ctx->dbg, cur_die, &sib_die, &dw_ctx->error);
            found = _find_func_die_by_symbol(dw_ctx, sib_die, ret_die,
                                             symbol); /* recur others */
        };
    }

    return found;
}

static bool _find_cu_by_symbol(dw_context_t *dw_ctx,
                               dw_cu_t **ret_node,
                               const char *symbol)
{
    dw_cu_t *ptr;
    Dwarf_Die cu_die, dumb_die; /* Don't care function DIE */
    Dwarf_Off off;
    list_for_each_entry(ptr, &dw_ctx->cus, list)
    {
        off = ptr->off;
        if (dwarf_offdie(dw_ctx->dbg, off, &cu_die, &dw_ctx->error) ==
            DW_DLV_OK) {
            bool got =
                _find_func_die_by_symbol(dw_ctx, cu_die, &dumb_die, symbol);
            dwarf_dealloc(dw_ctx->dbg, cu_die, DW_DLA_DIE);
            /* Check ret_die got */
            if (got) {
                *ret_node = ptr;
                dwarf_dealloc(dw_ctx->dbg, dumb_die, DW_DLA_DIE);
                return true;
            }
        }
    }

    return false;
}

static void _print_source(char *src_file, char *func_name, int lineno)
{
    FILE *f = fopen(src_file, "r");
    char *line = NULL;
    size_t len = 0;
    int nread = 0;
    while (nread < lineno && (getline(&line, &len, f) != -1)) {
        nread++;
    }

    fprintf(stdout, "Stopped at line %d, in %s():\n", lineno, func_name);
    fprintf(stdout, "%s\n", line);
    fclose(f);
}

void dw_print_source(dw_context_t *dw_ctx, uintptr_t addr)
{
    Dwarf_Die func_die = NULL;
    dw_get_func_die_by_addr(dw_ctx, &func_die, addr);

    if (!func_die) {
        fprintf(stderr, "ERROR: Get DIE failed\n");
        return;
    }

    char *func_name = NULL;
    dwarf_diename(func_die, &func_name, &dw_ctx->error);
    dwarf_dealloc(dw_ctx->dbg, func_die, DW_DLA_DIE);

    Dwarf_Line line_entry = NULL;
    dw_get_line_by_addr(dw_ctx, &line_entry, addr);
    if (!line_entry) {
        fprintf(stderr, "ERROR: Get line entry failed\n");
        return;
    }

    Dwarf_Unsigned line_no = 0;
    char *src_file = NULL;
    dwarf_lineno(line_entry, &line_no, &dw_ctx->error);
    dwarf_linesrc(line_entry, &src_file, &dw_ctx->error);

    if (src_file == NULL) {
        fprintf(stderr, "ERROR: Get source file failed\n");
    }

    _print_source(src_file, func_name, line_no);
}

int dw_init(dw_context_t *dw_ctx, const char *prog)
{
    int fd = -1;
    fd = open(prog, O_RDONLY);
    if (fd == -1)
        return -1;

    dw_ctx->fd = fd;

    /* Start initializing DWARF information */
    if (dwarf_init(fd, DW_DLC_READ, dw_ctx->errhand, dw_ctx->errarg,
                   &dw_ctx->dbg, &dw_ctx->error) != DW_DLV_OK) {
        fprintf(stderr, "ERROR: cannot do DWARF processing\n");
        return -1;
    }

    if (dwarf_get_aranges(dw_ctx->dbg, &dw_ctx->all_aranges, &dw_ctx->n_aranges,
                          &dw_ctx->error) != DW_DLV_OK) {
        fprintf(stderr, "ERROR: dwarf_get_aranges failed\n");
        return -1;
    }

    /* Load all CU DIE */
    INIT_LIST_HEAD(&dw_ctx->cus);
    _dw_load_cu(dw_ctx);

    return 0;
}

int dw_finish(dw_context_t *dw_ctx)
{
    dw_cu_t *ptr, *safe;
    list_for_each_entry_safe(ptr, safe, &dw_ctx->cus, list)
    {
        dwarf_srclines_dealloc(dw_ctx->dbg, ptr->lines, ptr->n_lines);
        list_del(&ptr->list);
        free(ptr);
    }

    dwarf_dealloc(dw_ctx->dbg, dw_ctx->all_aranges, DW_DLA_LIST);

    if (dwarf_finish(dw_ctx->dbg, &dw_ctx->error) != DW_DLV_OK) {
        fprintf(stderr, "ERROR: dwarf_finish failed!\n");
        return -1;
    }

    close(dw_ctx->fd);
    return 0;
}

bool dw_get_func_die_by_symbol(dw_context_t *dw_ctx,
                               Dwarf_Die *ret_die,
                               const char *symbol)
{
    dw_cu_t *ptr;
    Dwarf_Die cu_die;
    Dwarf_Off off;
    list_for_each_entry(ptr, &dw_ctx->cus, list)
    {
        off = ptr->off;
        if (dwarf_offdie(dw_ctx->dbg, off, &cu_die, &dw_ctx->error) ==
            DW_DLV_OK) {
            bool got =
                _find_func_die_by_symbol(dw_ctx, cu_die, ret_die, symbol);
            dwarf_dealloc(dw_ctx->dbg, cu_die, DW_DLA_DIE);
            /* Check ret_die got */
            if (got) {
                return true;
            }
        }
    }

    return false;
}

bool dw_get_func_die_by_addr(dw_context_t *dw_ctx,
                             Dwarf_Die *ret_die,
                             uintptr_t addr)
{
    dw_cu_t *cu = NULL;
    _find_cu_by_addr(dw_ctx, &cu, addr);

    if (!cu) {
        fprintf(stderr, "Get CU failed\n");
        return false;
    }

    Dwarf_Die cu_die = 0;
    if (dwarf_offdie(dw_ctx->dbg, cu->off, &cu_die, &dw_ctx->error) !=
        DW_DLV_OK) {
        fprintf(stderr, "off_die failed\n");
        return false;
    }

    int got = _find_func_die_by_addr(dw_ctx, cu_die, ret_die, addr);
    dwarf_dealloc(dw_ctx->dbg, cu_die, DW_DLA_DIE);

    return got;
}

bool dw_get_line_by_addr(dw_context_t *dw_ctx,
                         Dwarf_Line *ret_line,
                         uintptr_t addr)
{
    dw_cu_t *cu = NULL;
    _find_cu_by_addr(dw_ctx, &cu, addr);

    if (!cu) {
        fprintf(stderr, "ERROR: Get CU failed\n");
        return false;
    }

    Dwarf_Addr line_addr_cur = 0, line_addr_nxt = 0;
    for (Dwarf_Signed i = 0; i < cu->n_lines - 1; i++) {
        dwarf_lineaddr(cu->lines[i], &line_addr_cur, &dw_ctx->error);
        dwarf_lineaddr(cu->lines[i + 1], &line_addr_nxt, &dw_ctx->error);
        if (line_addr_cur <= addr && addr < line_addr_nxt) {
            *ret_line = cu->lines[i];
            return true;
        }
    }

    return false;
}

bool dw_get_addr_by_func_sym(dw_context_t *dw_ctx,
                          const char *func_name,
                          uintptr_t *addr)
{
    Dwarf_Die func_die = NULL;
    int got = dw_get_func_die_by_symbol(dw_ctx, &func_die, func_name);
    if (!got) {
        fprintf(stderr, "ERROR: Get function DIE failed\n");
        return false;
    }

    Dwarf_Addr lowpc;
    int ret = dwarf_lowpc(func_die, &lowpc, &dw_ctx->error);
    dwarf_dealloc(dw_ctx->dbg, func_die, DW_DLA_DIE);

    if (ret != DW_DLV_OK) {
        fprintf(stderr, "ERROR: Get function address failed\n");
        return false;
    }

    *addr = lowpc;
    return true;
}

bool dw_get_cu_by_file_name(dw_context_t *dw_ctx,
                            dw_cu_t **ret_node,
                            const char *file_name)
{
    dw_cu_t *ptr;
    Dwarf_Die cu_die;
    list_for_each_entry(ptr, &dw_ctx->cus, list)
    {
        if (dwarf_offdie(dw_ctx->dbg, ptr->off, &cu_die, &dw_ctx->error) ==
            DW_DLV_OK) {
            char **file_names = NULL;
            Dwarf_Signed fn_count = 0;
            dwarf_srcfiles(cu_die, &file_names, &fn_count, &dw_ctx->error);

            if (file_names != NULL) {
                for (Dwarf_Signed i = 0; i < fn_count; i++) {
                    if (strcmp(file_name, file_names[i]) == 0) {
                        *ret_node = ptr;
                        dwarf_dealloc(dw_ctx->dbg, cu_die, DW_DLA_DIE);
                        return true;
                    }
                }
            }

            dwarf_dealloc(dw_ctx->dbg, cu_die, DW_DLA_DIE);
        }
    }

    return false;
}

bool dw_get_addr_by_srcline(dw_context_t *dw_ctx,
                             const char *srcline,
                             uintptr_t *addr)
{
    char *buffer = strdup(srcline);

    char *file_name = strtok(buffer, ":");
    if (file_name == NULL)
        return false;

    char *line_str = strtok(NULL, ":");
    if (line_str == NULL)
        return false;

    int line, pos;
    int ret = sscanf(line_str, "%d%n", &line, &pos);
    if ((ret == 0) || ((size_t) pos != strlen(line_str)))
        return false;

    char file_path[MAX_BUFFER];
    char *exist = realpath(file_name, file_path);
    if (exist == NULL) {
        fprintf(stderr, "ERROR: Cannot find the path to %s\n", file_name);
        return false;
    }

    /* Find the CU node for the given file name */
    dw_cu_t *cu_node = NULL;
    dw_get_cu_by_file_name(dw_ctx, &cu_node, file_path);
    if (cu_node == NULL) {
        fprintf(stderr, "ERROR: Cannot find CU related to %s\n", file_name);
        return false;
    }

    if (line > cu_node->n_lines) {
        fprintf(stderr, "ERROR: Out of line range in %s\n", file_name);
        return false;
    }

    /* Find address of the given line number */
    Dwarf_Addr ret_addr = 0;
    Dwarf_Unsigned lineno = 0;
    for (Dwarf_Signed i = 0; i < cu_node->n_lines; i++) {
        if (dwarf_lineno(cu_node->lines[i], &lineno, &dw_ctx->error) !=
            DW_DLV_OK) {
            continue;
        }

        if ((int) lineno == line &&
            dwarf_lineaddr(cu_node->lines[i], &ret_addr, &dw_ctx->error) ==
                DW_DLV_OK) {
            /* Got target address */
            *addr = (uintptr_t) ret_addr;
            return true;
        }
    }


    fprintf(stderr, "ERROR: Get address of line %d in %s failed\n", line,
            file_name);
    return false;
}


bool dw_get_addr_by_line(dw_context_t *dw_ctx,
                         int line,
                         uintptr_t *addr)
{   
    dw_cu_t *cu_node;
    if(_find_cu_by_symbol(dw_ctx, &cu_node, "main") == false) {
        fprintf(stderr, "Found main faile\n");
        return false;
    }

    Dwarf_Die cu_die;
    if (dwarf_offdie(dw_ctx->dbg, cu_node->off, &cu_die, &dw_ctx->error) !=
        DW_DLV_OK) {
        fprintf(stderr, "ERROR: offdie failed\n");
        return false;
    }

    char *file_name = NULL;
    if(dwarf_diename(cu_die, &file_name, &dw_ctx->error) != DW_DLV_OK) {
        fprintf(stderr, "ERROR: Get DIE name failed\n");
        return false;
    }


    char srcline[MAX_BUFFER];
    snprintf(srcline, sizeof(srcline), "%s:%d", file_name, line);
    return dw_get_addr_by_srcline(dw_ctx, srcline, addr);
}