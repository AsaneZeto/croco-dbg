#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h> 

#include "debugger.h"
#include "linenoise.h"
#include "tools.h"
#include "register.h"

static debugger_t *tdb;
static cmd_element_t *curr_cmd = NULL;

/* Find the command handler */
static cmdhandler_t dbg_find_handler(char *cmd)
{
    if(!cmd)
        return NULL;

    cmd_element_t *ptr;
    list_for_each_entry(ptr, &tdb->list, list) {
        if (strcmp(cmd, ptr->abbr) == 0 || strcmp(cmd, ptr->cmd) == 0) {
                curr_cmd = ptr;
                return ptr->handler;
        }
    }
    
    return NULL;
}

/* Find the handler for the commands with options */
static cmdhandler_t _dbg_find_handler(struct list_head *head, char *opt)
{
    cmd_opt_t *ptr;
    list_for_each_entry(ptr, head, list) {
        if(strcmp(opt, ptr->opt) == 0) {
            return ptr->handler;
        }
    }

    return NULL;
}


static bool dbg_add_command(debugger_t *dbg, char *cmd, char *abbr,
                            cmdhandler_t handler, char *description)
{
    cmd_element_t *node = (cmd_element_t *)malloc(sizeof(cmd_element_t));

    if (!node)
        return false;

    node->cmd = cmd;
    node->abbr = abbr;
    node->description = description;
    node->handler = handler;

    INIT_LIST_HEAD(&node->list);
    INIT_LIST_HEAD(&node->options);
    list_add_tail(&node->list, &dbg->list);

    return true;
}

static bool dbg_add_option(debugger_t *dbg, char *cmd, char *opt, 
                           cmdhandler_t handler, char *description)
{   
    if(!dbg)
        return false;

    struct list_head *ptr;
    cmd_element_t *node_cmd;
    list_for_each(ptr, &dbg->list) {
        node_cmd = list_entry(ptr, cmd_element_t, list);
        if(strcmp(cmd, node_cmd->cmd) == 0 ||
           strcmp(cmd, node_cmd->abbr) == 0) {
            break;
        }
    }

    if(ptr == &dbg->list) {
        fprintf(stderr, "Failed adding %s option\n", cmd);
        return false;
    }

    cmd_opt_t *node_opt = (cmd_opt_t *)malloc(sizeof(cmd_opt_t));

    if (!node_opt)
        return false;

    node_opt->opt = opt;
    node_opt->handler = handler;
    node_opt->description = description;

    INIT_LIST_HEAD(&node_opt->list);
    list_add_tail(&node_opt->list, &node_cmd->options);

    return true;
}

static bool dbg_read_mem(debugger_t *dbg, uintptr_t addr, size_t *data)
{
    long ret = ptrace(PTRACE_PEEKTEXT, dbg->pid, (void *)addr, NULL);
    
    if (ret == -1) {
        fprintf(stderr, "Request error: Read memory\n");
        return false;
    }

    *data = (size_t) ret;
    return true;
}

static bool dbg_write_mem(debugger_t *dbg, uintptr_t addr, size_t data)
{
    int ret = ptrace(PTRACE_POKETEXT, dbg->pid, (void *)addr, data);

    if (ret == -1) {
        fprintf(stderr, "Request error: Write memory\n");
        return false;
    }

    return true;
}

static bool do_mem_read(int argc, char *argv[])
{   
    if (strlen(argv[2]) == 0 || (argv[2][0] != '0' || argv[2][1] != 'x')) {
        fprintf(stderr, "Invalid address.\n");
        return false;
    }

    uintptr_t addr = 0;
    size_t value;
    sscanf(argv[2], "0x%lx", &addr);
    dbg_read_mem(tdb, addr, &value);
    printf("%s: %ld\n", argv[2], value);

    return true;
}

static bool do_mem_write(int argc, char *argv[])
{   
    if (strlen(argv[2]) == 0 || (argv[2][0] != '0' || argv[2][1] != 'x')) {
        fprintf(stderr, "Invalid address.\n");
        return false;
    }

    uintptr_t addr = 0;
    sscanf(argv[2], "0x%lx", &addr);

    char *end;
    size_t value = strtoul(argv[3], &end, 10);

    if ((end == argv[3]) || (*end != '\0')) {
        fprintf(stderr, "Invalid value.\n");
        return false;
    }

    return dbg_write_mem(tdb, addr, value);
}

static bool do_reg_dump(int argc, char *argv[])
{
    reg_dump(tdb->pid);
    return true;
}

static bool do_reg_read(int argc, char *argv[])
{
    if (strlen(argv[2]) == 0) {
        fprintf(stderr, "Invalid register.\n");
        return false;
    }

    reg_idx r = reg_get_idx_name(argv[2]);
    size_t value;
    reg_get_value(tdb->pid, r, &value);
    printf("%s: 0x%lx\n", argv[2], value);

    return true;
}

static bool do_reg_write(int argc, char *argv[])
{
    if (strlen(argv[2]) == 0) {
        fprintf(stderr, "Invalid register.\n");
        return false;
    }

    reg_idx r = reg_get_idx_name(argv[2]);
    
    char *end;
    size_t value = strtoul(argv[3], &end, 10);

    if ((end == argv[3]) || (*end != '\0')) {
        fprintf(stderr, "Invalid value.\n");
        return false;
    }

    return reg_set_value(tdb->pid, r, value);
}

static bool do_reg_mem(int argc, char *argv[])
{   
    if(argc < 2) {
        fprintf(stderr, "Too few arguments\n");
        return false;
    }

    cmdhandler_t handler = _dbg_find_handler(&curr_cmd->options, argv[1]);
    if(handler) {
        return handler(argc, argv);
    }

    fprintf(stderr, "Unknown argument.\n");
    return false;
}

static bool do_break_dump(int argc, char *argv[])
{   
    dbe_dump_bp(&tdb->dbe);
    return true;
}

static bool do_break(int argc, char *argv[])
{
    /* Assume the address is Hexadecimal: 0xADDRESS */
    printf("%s\n", curr_cmd->cmd);

    if(argc < 2) {
        fprintf(stderr, "Too few arguments\n");
        return false;
    }

    if(argv[1][0] == '0' && argv[1][1] == 'x') {
        uintptr_t addr = 0;
        sscanf(argv[1], "0x%lx", &addr);
        dbe_set_bp(&tdb->dbe, &addr);

        return true;
    } 

    cmdhandler_t handler = _dbg_find_handler(&curr_cmd->options, argv[1]);
    if(handler)
        return handler(argc, argv);

    fprintf(stderr, "Unknown option\n");
    return false;
}

static void dbg_step_bp(debugger_t *dbg)
{   
    /* Get next instruction */
    size_t pc = 0;
    reg_get_value(dbg->pid, rip, &pc);
    uintptr_t addr = (uintptr_t)(pc - 1);
    
    char key[17];
    snprintf(key, 17, "%lx", addr);
    size_t *data = NULL;
    if(hashtbl_search(dbg->dbe.hashtbl, key, (void **)&data)) {
        uintptr_t prev_inst = addr;
        reg_set_value(dbg->pid, rip, (size_t)prev_inst);

        size_t idx = *data - 1;
        bp_disable(&dbg->dbe.bp[idx]);
        ptrace(PTRACE_SINGLESTEP, dbg->pid, NULL, NULL);
        wait_for_signal(dbg->pid);
        bp_enable(&dbg->dbe.bp[idx]);
    }
    return;
}

static bool do_continue(int argc, char *argv[])
{   
    dbg_step_bp(tdb);
    ptrace(PTRACE_CONT, tdb->pid, NULL, NULL);
    wait_for_signal(tdb->pid);

    return true;
}

static bool do_quit(int argc, char *argv[])
{   
    dbg_close(tdb);
    exit(0);

    return true;
}

static bool do_help(int argc, char *argv[])
{   
    cmd_element_t *ptr;
    list_for_each_entry(ptr, &tdb->list, list) {
        printf("%s (%s): %s\n", ptr->cmd, ptr->abbr, ptr->description);
        if(!list_empty(&ptr->options)) {
            cmd_opt_t *pptr;
            list_for_each_entry(pptr, &ptr->options, list) {
                printf("\t%5s\n", pptr->description);
            }
        }
    }

    return true;
}

static bool do_vmmap(int argc, char *argv[]) {
    char path[MAX_BUFFER];
    snprintf(path, sizeof(path), "/proc/%d/maps", tdb->pid);
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    if(!f) {
        fprintf(stderr, "ERROR: Access information of mapped memory region of process %d\n", tdb->pid);
        return false;
    }

    while((nread = getline(&line, &len, f)) != -1) {
        printf("%s", line);
    }

    free(line);
    fclose(f);
    return true;
}

static char **dbg_command_parser(debugger_t *dbg, char *cmd, int *argc)
{   
    char _cmd[MAX_BUFFER];
    strncpy(_cmd, cmd, strlen(cmd)+1);

    char **_argv = calloc(MAX_ARGC, sizeof(char *));
    int _argc = 0;
    char *token = strtok(_cmd, " ");

    while(token != NULL) {
        /* Skip multiple spaces */
        if (strcmp(token, " ") == 0){
            token = strtok(NULL, " ");
            continue;
        }

        if(_argc >= MAX_ARGC) {
            fprintf(stderr, "The number of arguments exceeds the limit\n");
            return NULL;
        }

        _argv[_argc++] = token;
        token = strtok(NULL, " ");
    };

    *argc = _argc;
    return _argv;
}

void dbg_init(debugger_t *dbg, pid_t pid, const char *prog)
{
    dbg->pid = pid;
    dbg->prog = prog;

    INIT_LIST_HEAD(&dbg->list);
    dbg_add_command(dbg, "help", "h", do_help, "Show command description");
    dbg_add_command(dbg, "continue", "cont", do_continue, "Restart the stopped tracee process");
    dbg_add_command(dbg, "quit", "q", do_quit, "Quit tinydbg");
    dbg_add_command(dbg, "break", "b", do_break, "Set breakpoint");
    dbg_add_option(dbg, "break", "dump", do_break_dump, "Dump: all breakpoint (if any)");

    dbg_add_command(dbg, "reg", "r", do_reg_mem, "Register oprations");
    dbg_add_option(dbg, "reg", "dump", do_reg_dump, "dump: Dump all register information");
    dbg_add_option(dbg, "reg", "read", do_reg_read, "read {register}: Read value from a register");
    dbg_add_option(dbg, "reg", "write", do_reg_write, "write {register} {VALUE}: Write value to a register");

    dbg_add_command(dbg, "mem", "m", do_reg_mem, "Memory oprations");
    dbg_add_option(dbg, "mem", "read", do_mem_read, "read {0xADDRESS}: Read value from an address");
    dbg_add_option(dbg, "mem", "write", do_mem_write, "write {0xADDRESS} {VALUE}: Write value to an address");

    dbg_add_command(dbg, "vmmap", "vmmap", do_vmmap, "Show virtual memory layout");

    dbe_init(&dbg->dbe);

    tdb = dbg;
}

void dbg_run(debugger_t *dbg)
{
    wait_for_signal(dbg->pid);

    char *cmd = NULL;
    int argc = 0;
    char **argv = NULL;
    while ((cmd = linenoise("tinydbg> ")) != NULL) {
        argv = dbg_command_parser(dbg, cmd, &argc);

        if(!argv) {
            fprintf(stderr, "Error: Parse command\n");
            continue;
        }

        cmdhandler_t handler = dbg_find_handler(argv[0]);
        if(handler)
            handler(argc, argv);
        else 
            fprintf(stderr, "Unknown Command.\n");

        linenoiseHistoryAdd(cmd);
        linenoiseFree(cmd);
        free(argv);
    }
}

void dbg_close(debugger_t *dbg)
{   
    if(!dbg)
        return;

    cmd_element_t *ptr, *safe;
    cmd_opt_t *optr, *osafe;
    list_for_each_entry_safe (ptr, safe, &dbg->list, list) {
        if (!list_empty(&ptr->options)) {
            /* Free option nodes first if any */
            list_for_each_entry_safe(optr, osafe, &ptr->options, list) {
                list_del(&optr->list);
                free(optr);
            }
        }

        list_del(&ptr->list);
        free(ptr);
    }

    dbe_close(&dbg->dbe);
    free(dbg);
}