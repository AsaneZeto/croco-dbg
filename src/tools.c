#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/personality.h>

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

static void handle_sigtrap(pid_t pid, siginfo_t info)
{
    switch (info.si_code) {
        case SI_KERNEL:
        case TRAP_BRKPT:
            /* IF trapped, set PC as current position */
            uintptr_t addr = get_pc(pid);
            set_pc(pid, addr-1);
            fprintf(stdout, "Hit breakpoint 0x%lx\n", get_pc(pid));
            break;
        case TRAP_TRACE:
            break;
        default:
            break;
    }

    return;
}

void wait_for_signal(pid_t pid)
{   
    /* Parent handles the signals from child process */
    int wait_status;
    int options = 0;
    waitpid(pid, &wait_status, options);

    siginfo_t siginfo;
    ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo); /* Get signal from child */

    switch (siginfo.si_signo) {
        case SIGTRAP:
            handle_sigtrap(pid, siginfo);
            break;
        case SIGSEGV:
            fprintf(stderr, "SIGSEGV, Signal code: %d\n", siginfo.si_code);
            break;
        default:
            // fprintf(stdout, "Got signal %s\n", strsignal(siginfo.si_signo));
            break;
    }
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