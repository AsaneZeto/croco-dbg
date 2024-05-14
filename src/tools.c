#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "debugger.h"
#include "dwarftool.h"
#include "breakpoint.h"
#include "register.h"

uintptr_t get_pc(pid_t pid)
{
    size_t pc = 0;
    reg_get_value(pid, rip, &pc);
    return (uintptr_t) pc;
}

void set_pc(pid_t pid, uintptr_t addr)
{
    reg_set_value(pid, rip, (size_t) addr);
}

void exec_prog(const char *prog)
{
    personality(ADDR_NO_RANDOMIZE); /* Disable ASLR */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        fprintf(stderr, "ERROR: tracing executable\n");
        return;
    }
    execl(prog, prog, NULL);
}


static bool is_number(const char *str)
{
    size_t len = strlen(str);
    for(size_t i = 0; i < len; i++) {
        if(!isdigit(str[i]))
            return false;
    }

    return true;
}

int parse_break_arg(const char *arg) 
{      
    size_t len = strlen(arg);
    if (len < 1)
        return -1;
    
    if ((len >= 2) && (arg[0] == '0' && arg[1] == 'x')) {
        return BP_HEXADDR;
    } else if (strchr(arg, ':') != NULL) {
        return BP_SRCLINE;
    } else if (is_number(arg)) {
        return BP_LINE;
    } else if (strcmp(arg, "dump") != 0) {
        return BP_SYMBOL;
    }

    return -1;
}