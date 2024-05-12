#pragma once

#include <stddef.h>
#include <stdint.h>

#define container_of(ptr, type, member)                            \
    __extension__({                                                \
        const __typeof__(((type *) 0)->member) *__pmember = (ptr); \
        (type *) ((char *) __pmember - offsetof(type, member));    \
    })

void exec_prog(const char *prog);
uintptr_t get_pc(pid_t pid);
void set_pc(pid_t pid, uintptr_t addr);
