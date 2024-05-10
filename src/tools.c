#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/personality.h>

void wait_for_signal(pid_t pid)
{
    int wait_status;
    int options = 0;
    waitpid(pid, &wait_status, options);
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