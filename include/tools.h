#ifndef TOOLS_H
#define TOOLS_H

#include <stddef.h>

#define container_of(ptr, type, member)                            \
    __extension__({                                                \
        const __typeof__(((type *) 0)->member) *__pmember = (ptr); \
        (type *) ((char *) __pmember - offsetof(type, member));    \
    })

void wait_for_signal(pid_t pid);
void exec_prog(const char *prog);

#endif