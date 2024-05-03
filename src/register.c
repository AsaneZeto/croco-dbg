#include <sys/user.h>
#include <sys/ptrace.h>

#include "register.h"

bool get_reg_value(pid_t pid, reg_idx r, size_t *value)
{   
    if (r == -1 || r >= N_REG) {
        fprintf(stderr, "Invalid register number.\n");
        return false;
    }

    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    *value = *(size_t *)(&reg + r);
    return true;
}

bool get_reg_value_dwf(pid_t pid, int dwarf_r, size_t *value)
{
    get_reg_idx_dwf(dwarf_r);
    return get_reg_value(pid, idx, value);
}

bool get_reg_value_name(pid_t pid, const char *name, size_t *value)
{
    reg_idx r = get_reg_idx(name);
    return get_reg_value(pid, r, value);
}

reg_idx get_reg_idx_dwf(int dwarf_r)
{
    size_t idx = 0;
    for(; idx < N_REG; idx++) {
        if (reg_descriptors[idx].dwarf_r == dwarf_r)
            break;
    }

    if(idx >= N_REG)
        return -1;

    return idx;
}

reg_idx get_reg_idx_name(const char *name)
{
    size_t idx = 0;
    for(; idx < N_REG; idx++) {
        if (strcmp(name, reg_descriptors[idx].name) == 0)
            break;
    }

    if(idx >= N_REG)
        return -1;

    return idx;
}

bool set_reg_value(pid_t pid, reg_idx r, size_t value);