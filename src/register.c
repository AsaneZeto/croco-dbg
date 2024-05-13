#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "register.h"

void reg_dump(pid_t pid)
{
    fprintf(stdout, "Dumping Registers:\n");
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    size_t value = 0;
    for (size_t r = 0; r < N_REG; r++) {
        reg_get_value(pid, r, &value);
        fprintf(stdout, "%s: 0x%lx\n", reg_get_name(r), value);
    }
}

bool reg_get_value(pid_t pid, reg_idx r, size_t *value)
{
    if (r >= N_REG) {
        fprintf(stderr, "ERROR: Invalid register number\n");
        return false;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    *value = *((size_t *) (&regs) + r);
    return true;
}

bool reg_get_value_dwf(pid_t pid, int dwarf_r, size_t *value)
{
    reg_idx r = reg_get_idx_dwf(dwarf_r);
    return reg_get_value(pid, r, value);
}

bool reg_get_value_name(pid_t pid, const char *name, size_t *value)
{
    reg_idx r = reg_get_idx_name(name);
    return reg_get_value(pid, r, value);
}

const char *reg_get_name(reg_idx r)
{
    return reg_descriptors[r].name;
}

reg_idx reg_get_idx_dwf(int dwarf_r)
{
    size_t idx = 0;
    for (; idx < N_REG; idx++) {
        if (reg_descriptors[idx].dwarf_r == dwarf_r)
            break;
    }

    if (idx >= N_REG)
        return N_REG;

    return idx;
}

reg_idx reg_get_idx_name(const char *name)
{
    size_t idx = 0;
    for (; idx < N_REG; idx++) {
        if (strcmp(name, reg_descriptors[idx].name) == 0)
            break;
    }

    if (idx >= N_REG)
        return N_REG;

    return idx;
}

bool reg_set_value(pid_t pid, reg_idx r, size_t value)
{
    if (r >= N_REG) {
        fprintf(stderr, "ERROR: Invalid register number\n");
        return false;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    *((size_t *) (&regs) + r) = value;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    return true;
}
