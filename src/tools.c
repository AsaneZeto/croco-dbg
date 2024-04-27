#include <sys/types.h>
#include <sys/wait.h>

void wait_for_signal(pid_t pid)
{
    int wait_status;
    int options = 0;
    waitpid(pid, &wait_status, options);
}