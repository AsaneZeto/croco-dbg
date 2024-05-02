#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

#include "breakpoint.h"

// static uint8_t INT3 = 0xcc;
const uint8_t INT3[1] = {0xcc};

void bp_init(breakpoint_t *bp, pid_t pid, uintptr_t addr)
{
    bp->pid = pid;
    bp->addr = addr;
    bp->is_enable = false;
    bp->saved_data = 0;
    snprintf(bp->addr_key, 17, "%lx", addr);
}

void bp_enable(breakpoint_t *bp)
{
    printf("0x%lx\n", bp->addr);
    size_t data = ptrace(PTRACE_PEEKDATA, bp->pid, (void *) bp->addr, NULL);
    bp->saved_data = (uint8_t)(data & 0xff);
    size_t data_with_int3 = data;
    memcpy(&data_with_int3, INT3, sizeof(INT3));
    ptrace(PTRACE_POKEDATA, bp->pid, (void *) bp->addr, data_with_int3);

    bp->is_enable = true;
}

void bp_disable(breakpoint_t *bp)
{
    size_t data = ptrace(PTRACE_PEEKDATA, bp->pid, bp->addr, NULL);
    size_t restored_data =  ((data & ~(0xff)) | bp->saved_data);
    ptrace(PTRACE_POKEDATA, bp->pid, bp->addr, restored_data);

    bp->is_enable = false;
}