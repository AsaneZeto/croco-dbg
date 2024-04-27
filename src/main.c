#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "debugger.h"
#include "debuggee.h"

static char *prog;

int main(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Program must be specified.\n");
        return 1;
    }

    prog = argv[1];
    pid_t pid = fork();

    if(pid == 0) {
        // Child Process : Tracee
        dbe_start(prog);
    } else if(pid >= 1) {
        // Parent Process : Tracer
        debugger_t *dbg = malloc(sizeof(debugger_t));

        if(!dbg) {
            fprintf(stderr, "Failed allocating memory\n");
            abort();
        }

        dbg_init(dbg, pid, prog);
        dbg_run(dbg);
        dbg_close(dbg);
    }

    return 0;
}