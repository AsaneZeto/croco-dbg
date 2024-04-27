#ifndef DEBUGGER_H
#define DEBUGGER_H

#define MAX_CMD_BUFFER 1024
#define MAX_ARGC 16

#include <sys/ptrace.h>
#include <sys/types.h>
#include <stdbool.h>

typedef struct {
    pid_t pid;
    const char *prog;
} debugger_t;

void dbg_init(debugger_t *dbg, pid_t pid, const char *prog);
void dbg_run(debugger_t *dbg);
void dbg_close(debugger_t *dbg);
void dbg_command_handler(debugger_t *dbg, char * cmd);
void dbg_continue(debugger_t *dbg);
void dbg_quit(debugger_t *dbg);
#endif