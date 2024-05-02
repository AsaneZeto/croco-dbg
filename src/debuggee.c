#include <stdio.h>
#include <stdlib.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <unistd.h>

#include "debuggee.h"
#include "debugger.h"
#include "tools.h"

void dbe_init(debuggee_t *dbe) 
{
    dbe->hashtbl = calloc(1, sizeof(hashtbl_t));
    hashtbl_create(MAX_BP, dbe->hashtbl);
    dbe->nBp = 0;
}


void dbe_start(const char *prog) 
{
    personality(ADDR_NO_RANDOMIZE); /* Disable ASLR */
    if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        fprintf(stderr, "Error in ptrace\n");
        return;
    }
    execl(prog, prog, NULL);
}

bool dbe_set_bp(debuggee_t *dbe, uintptr_t *addr_p)
{
    if(dbe->nBp + 1 > MAX_BP) {
        fprintf(stderr, "The number of breakpoints reach max limis.\n");
        return false;
    }
     
    // breakpoint_t bp;
    printf("%d\n", container_of(dbe, debugger_t, dbe)->pid);
    bp_init(&dbe->bp[dbe->nBp], container_of(dbe, debugger_t, dbe)->pid, *addr_p);
    bp_enable(&dbe->bp[dbe->nBp]);

    if(!hashtbl_add(dbe->hashtbl, dbe->bp[dbe->nBp].addr_key, (void*)addr_p)) {
        fprintf(stderr, "Failed record breakpoint.\n");
        return false;
    }
    
    dbe->nBp++;

    printf("Set breakpoint at address 0x%lx\n", *addr_p);
    return true;
}

void dbe_dump_bp(debuggee_t *dbe)
{
    if(!dbe)
        return;
    
    if(dbe->nBp == 0) {
        fprintf(stderr, "No breakpoint exists.\n");
        return;
    }
    
    uintptr_t *data = NULL;
    for(size_t i = 0; i < dbe->nBp; i++) {
        hashtbl_search(dbe->hashtbl, dbe->bp[i].addr_key, (void **) &data);
        printf("0x%lx\n", *data);
    }
}