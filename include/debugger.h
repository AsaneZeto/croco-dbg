#pragma once

#define MAX_BUFFER 1024
#define MAX_ARGC 16

#include <stdbool.h>
#include <sys/ptrace.h>
#include <sys/types.h>

#include "debuggee.h"
#include "dwarftool.h"
#include "list.h"

typedef bool (*cmdhandler_t)(int argc, char *argv[]);

typedef struct {
    pid_t pid;
    const char *prog;      /* Program name */
    uintptr_t load_addr;   /* Program counter base */
    struct list_head list; /* Each node represents a command */
    debuggee_t dbe;        /* Maintains debuge information */
    dw_context_t dw_ctx;
} debugger_t;

typedef struct {
    char *cmd;            /* Command name */
    char *abbr;           /* Command abbreviation */
    char *description;    /* Command description */
    cmdhandler_t handler; /* A specific function that deal with this command */
    struct list_head list;
    struct list_head
        options; /* Each node represents an option for this command */
} cmd_element_t;

typedef struct {
    char *opt;
    char *description;
    cmdhandler_t handler;
    struct list_head list;
} cmd_opt_t;

void dbg_init(debugger_t *dbg, pid_t pid, const char *prog);
void dbg_run(debugger_t *dbg);
void dbg_close(debugger_t *dbg);
