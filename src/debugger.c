#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include "linenoise.h"
#include "debugger.h"
#include "tools.h"

void dbg_init(debugger_t *dbg, pid_t pid, char *prog)
{
    dbg->pid = pid;
    dbg->prog = prog;
}

void dbg_continue(debugger_t *dbg)
{
    ptrace(PTRACE_CONT, dbg->pid, NULL, NULL);
    wait_for_signal(dbg->pid);
}

void dbg_command_handler(debugger_t *dbg, char *cmd)
{   
    char _cmd[MAX_CMD_BUFFER];
    strncpy(_cmd, cmd, strlen(cmd)+1);
    
    char *_argv[MAX_ARGC];
    int _argc = 0;
    char *token = strtok(_cmd, " ");

    while(token != NULL) {
        /* Avoid multiple spaces */
        if (strcmp(token, " ")){
            token = strtok(NULL, " ");
            continue;
        }

        if(_argc >= MAX_ARGC) {
            fprintf(stderr, "The number of arguments exceeds the limit\n");
            return;
        }

        _argv[_argc++] = token;
        token = strtok(NULL, " ");
    };

    if(strcmp(_argv[0], "cont") || strcmp(_argv[0], "continue")) {
        printf("Continue\n");
        dbg_continue(dbg);
    } else {
        fprintf(stderr, "Unknown Command\n");
    }
}

void dbg_run(debugger_t *dbg)
{
    wait_for_signal(dbg->pid);

    char *cmd = NULL;
    while((cmd = linenoise("tinydbg> ")) != NULL) {
        dbg_command_handler(dbg, cmd);
        linenoiseHistoryAdd(cmd);
        linenoiseFree(cmd);
    }
}

void dbg_close(debugger_t *dbg)
{
    free(dbg->prog);
    free(dbg);
}