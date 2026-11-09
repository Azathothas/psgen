/*
 * Run a command with one syscall denied by seccomp.
 *
 *   deny_syscall <syscall-name> <program> [args...]
 *
 * The filter returns EPERM for the named syscall and allows everything else,
 * so a process that handles the failure keeps running. Tests use it to check
 * the paths that only run when a syscall fails: psgen must not panic and must
 * not leave a run it cannot stop.
 *
 * Build:  cc -O2 -o deny_syscall deny_syscall.c
 * It needs no libseccomp: the BPF program is built by hand, which also means it
 * works on a musl box with no package manager.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

struct named {
    const char *name;
    int nr;
};

static const struct named CALLS[] = {
#ifdef __NR_getrandom
    {"getrandom", __NR_getrandom},
#endif
#ifdef __NR_memfd_create
    {"memfd_create", __NR_memfd_create},
#endif
#ifdef __NR_pidfd_open
    {"pidfd_open", __NR_pidfd_open},
#endif
#ifdef __NR_pidfd_send_signal
    {"pidfd_send_signal", __NR_pidfd_send_signal},
#endif
#ifdef __NR_close_range
    {"close_range", __NR_close_range},
#endif
#ifdef __NR_unshare
    {"unshare", __NR_unshare},
#endif
#ifdef __NR_pipe2
    {"pipe2", __NR_pipe2},
#endif
#ifdef __NR_fork
    {"fork", __NR_fork},
#endif
#ifdef __NR_setuid
    {"setuid", __NR_setuid},
#endif
#ifdef __NR_mount
    {"mount", __NR_mount},
#endif
    {NULL, -1},
};

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <syscall> <program> [args...]\n", argv[0]);
        return 2;
    }
    int nr = -1;
    for (const struct named *c = CALLS; c->name; c++) {
        if (strcmp(c->name, argv[1]) == 0) {
            nr = c->nr;
            break;
        }
    }
    if (nr < 0) {
        fprintf(stderr, "deny_syscall: unknown or unsupported syscall %s\n", argv[1]);
        return 2;
    }
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return 2;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("prctl(PR_SET_SECCOMP)");
        return 2;
    }
    execv(argv[2], &argv[2]);
    perror("execv");
    return 2;
}
