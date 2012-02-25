#ifndef PTRACERT_H
#define PTRACERT_H

#include <sys/wait.h>

#define EVENT_NONE 1 << 0
#define EVENT_SYSCALL 1 << 1
#define EVENT_SIGNAL 1 << 2

struct soxy_event_type {
    /* Fix this */
    int type;
};

struct soxy_event {
    struct soxy_event_type type;
    pid_t pid;
    int syscall_num;
    long signal_num;
};

int fork_trace_exec(int argc, char **argv);
int wait_for_syscall(struct soxy_event* s);

#endif
