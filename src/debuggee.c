#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>

#include "debuggee.h"

void dbe_start(const char *prog) {
    if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        fprintf(stderr, "Error in ptrace\n");
        return;
    }
    execl(prog, prog, NULL);
}