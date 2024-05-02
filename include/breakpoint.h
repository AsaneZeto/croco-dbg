#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#define MAX_BP 16

typedef struct {
    pid_t pid;
    uintptr_t addr;
    bool is_enable;
    uint8_t saved_data;
    char addr_key[17];
} breakpoint_t;

void bp_init(breakpoint_t *bp, pid_t pid, uintptr_t addr);
void bp_enable(breakpoint_t *bp);
void bp_disable(breakpoint_t *bp);

#endif