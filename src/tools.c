#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/personality.h>

#include "debugger.h"
#include "register.h"
#include "dwarftool.h"

uintptr_t get_pc(pid_t pid)
{
    size_t pc = 0;
    reg_get_value(pid, rip, &pc);
    return (uintptr_t)pc;
}

void set_pc(pid_t pid, uintptr_t addr)
{
    reg_set_value(pid, rip, (size_t) addr);
}

void exec_prog(const char *prog)
{
    personality(ADDR_NO_RANDOMIZE); /* Disable ASLR */
    if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        fprintf(stderr, "Error in ptrace\n");
        return;
    }
    execl(prog, prog, NULL);
}