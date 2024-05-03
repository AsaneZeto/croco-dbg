#ifndef REGISTER_H
#define REGISTER_H

#include <stdint.h>

#ifdef __x86_64__
#define N_REG 27
/* 
A subset of DWARF Register Number Mapping (Keep relative order)
with some replacement 
Ref: 1. https://www.uclibc.org/docs/psABI-x86_64.pdf 
     2. https://blog.tartanllama.xyz/writing-a-linux-debugger-registers
*/
typedef enum reg {
    r15, r14, r13, r12,
    rbp, rbx, r11, r10,
    r9,  r8,  rax, rcx,
    rdx, rsi, rdi, orig_rax,
    rip, cs,  rflags,
    rsp, ss,
    fs_base, gs_base,
    ds, es, fs, gs
} reg_idx;

typedef struct {
    reg_idx r;        /* Register index for tinydbg */
    int dwarf_r;      /* Real dwarf register number */
    const char *name; /* Register name */
} reg_descriptor_t;

/* The layout follows usr/include/sys/user.h */
const reg_descriptor_t reg_descriptors[N_REG] = {
    { r15, 15, "r15" },
    { r14, 14, "r14" },
    { r13, 13, "r13" },
    { r12, 12, "r12" },
    { rbp, 6, "rbp" },
    { rbx, 3, "rbx" },
    { r11, 11, "r11" },
    { r10, 10, "r10" },
    { r9, 9, "r9" },
    { r8, 8, "r8" },
    { rax, 0, "rax" },
    { rcx, 2, "rcx" },
    { rdx, 1, "rdx" },
    { rsi, 4, "rsi" },
    { rdi, 5, "rdi" },
    { orig_rax, -1, "orig_rax" },
    { rip, -1, "rip" },
    { cs, 51, "cs" },
    { rflags, 49, "eflags" },
    { rsp, 7, "rsp" },
    { ss, 52, "ss" },
    { fs_base, 58, "fs_base" },
    { gs_base, 59, "gs_base" },
    { ds, 53, "ds" },
    { es, 50, "es" },
    { fs, 54, "fs" },
    { gs, 55, "gs" },
};


bool get_reg_value(pid_t pid, reg_idx r, size_t *value);
bool get_reg_value_dwf(pid_t pid, int dwarf_r, size_t *value);
bool get_reg_value_name(pid_t pid, const char *name, size_t *value);

bool set_reg_value(pid_t pid, reg_idx r, size_t value);

char *get_reg_name(size_t r);

reg_idx get_reg_idx_dwf(int dwarf_r);
reg_idx get_reg_idx_name(const char *name);

#else
#error "Unsupported Architecture"
#endif

#endif