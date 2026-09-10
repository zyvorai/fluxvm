// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

static cpu_set_t *alloc_mask(size_t *size, int *ncpus)
{
    long n = sysconf(_SC_NPROCESSORS_CONF);
    cpu_set_t *set;

    if (n < 1)
        n = 1024;
    if (n > 1048576)
        n = 1048576;
    *ncpus = (int)n;
    *size = CPU_ALLOC_SIZE(*ncpus);
    set = CPU_ALLOC(*ncpus);
    if (set)
        CPU_ZERO_S(*size, set);
    return set;
}

static int parse_cpu_list(const char *text, cpu_set_t *set, size_t size, int ncpus)
{
    char *copy = strdup(text);
    char *save = NULL;
    char *tok;
    int seen = 0;

    if (!copy)
        return -1;
    for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        char *dash = strchr(tok, '-');
        long first, last;
        char *end = NULL;

        if (dash) {
            *dash = '\0';
            first = strtol(tok, &end, 10);
            if (!end || *end) {
                free(copy);
                return -1;
            }
            last = strtol(dash + 1, &end, 10);
            if (!end || *end) {
                free(copy);
                return -1;
            }
        } else {
            first = strtol(tok, &end, 10);
            if (!end || *end) {
                free(copy);
                return -1;
            }
            last = first;
        }
        if (first < 0 || last < first || last >= ncpus) {
            free(copy);
            return -1;
        }
        for (long cpu = first; cpu <= last; cpu++) {
            CPU_SET_S((int)cpu, size, set);
            seen = 1;
        }
    }
    free(copy);
    return seen ? 0 : -1;
}

static void print_mask(cpu_set_t *set, size_t size, int ncpus)
{
    int first = 1;

    putchar('"');
    for (int cpu = 0; cpu < ncpus; cpu++) {
        if (!CPU_ISSET_S(cpu, size, set))
            continue;
        if (!first)
            putchar(',');
        printf("%d", cpu);
        first = 0;
    }
    putchar('"');
}

static int get_cmd(pid_t tid)
{
    size_t size;
    int ncpus;
    cpu_set_t *set = alloc_mask(&size, &ncpus);
    struct sched_param param = {};
    int policy;

    if (!set)
        return 4;
    if (sched_getaffinity(tid, size, set)) {
        fprintf(stderr, "sched_getaffinity(%d): %s\n", tid, strerror(errno));
        CPU_FREE(set);
        return 4;
    }
    policy = sched_getscheduler(tid);
    if (policy < 0 || sched_getparam(tid, &param)) {
        fprintf(stderr, "scheduler query(%d): %s\n", tid, strerror(errno));
        CPU_FREE(set);
        return 4;
    }
    printf("{\"tid\":%d,\"policy\":%d,\"priority\":%d,\"cpus\":", tid, policy, param.sched_priority);
    print_mask(set, size, ncpus);
    puts("}");
    CPU_FREE(set);
    return 0;
}

static int set_ext_cmd(pid_t tid, const char *cpus)
{
    size_t size;
    int ncpus;
    cpu_set_t *old = alloc_mask(&size, &ncpus);
    cpu_set_t *set = NULL;
    struct sched_param param = { .sched_priority = 0 };
    int rc = 4;

    if (!old)
        return 4;
    set = CPU_ALLOC(ncpus);
    if (!set)
        goto out;
    CPU_ZERO_S(size, set);
    if (parse_cpu_list(cpus, set, size, ncpus)) {
        fprintf(stderr, "invalid CPU list: %s\n", cpus);
        rc = 2;
        goto out;
    }
    if (sched_getaffinity(tid, size, old)) {
        fprintf(stderr, "sched_getaffinity(%d): %s\n", tid, strerror(errno));
        goto out;
    }
    if (sched_setaffinity(tid, size, set)) {
        fprintf(stderr, "sched_setaffinity(%d): %s\n", tid, strerror(errno));
        goto out;
    }
    if (sched_setscheduler(tid, SCHED_EXT, &param)) {
        int saved = errno;
        (void)sched_setaffinity(tid, size, old);
        fprintf(stderr, "sched_setscheduler(SCHED_EXT,%d): %s\n", tid, strerror(saved));
        goto out;
    }
    rc = 0;
out:
    if (set)
        CPU_FREE(set);
    CPU_FREE(old);
    return rc;
}

static int restore_cmd(pid_t tid, const char *policy_s, const char *prio_s, const char *cpus)
{
    char *end = NULL;
    long policy = strtol(policy_s, &end, 10);
    long prio;
    size_t size;
    int ncpus;
    cpu_set_t *set = NULL;
    cpu_set_t *old = NULL;
    int old_policy;
    struct sched_param param = {0};
    struct sched_param old_param = {0};
    int rc = 4;

    if (!end || *end || policy < 0 || policy > 64)
        return 2;
    prio = strtol(prio_s, &end, 10);
    if (!end || *end || prio < 0 || prio > 99)
        return 2;
    set = alloc_mask(&size, &ncpus);
    if (!set)
        return 4;
    old = CPU_ALLOC(ncpus);
    if (!old)
        goto out;
    CPU_ZERO_S(size, old);
    if (parse_cpu_list(cpus, set, size, ncpus)) {
        rc = 2;
        goto out;
    }
    old_policy = sched_getscheduler(tid);
    if (old_policy < 0 || sched_getparam(tid, &old_param) || sched_getaffinity(tid, size, old)) {
        fprintf(stderr, "capture current state(%d): %s\n", tid, strerror(errno));
        goto out;
    }
    param.sched_priority = (int)prio;
    if (sched_setscheduler(tid, (int)policy, &param)) {
        fprintf(stderr, "restore scheduler(%d): %s\n", tid, strerror(errno));
        goto out;
    }
    if (sched_setaffinity(tid, size, set)) {
        int saved = errno;
        (void)sched_setscheduler(tid, old_policy, &old_param);
        (void)sched_setaffinity(tid, size, old);
        fprintf(stderr, "restore affinity(%d): %s; reverted scheduler/affinity best-effort\n", tid, strerror(saved));
        goto out;
    }
    rc = 0;
out:
    if (old)
        CPU_FREE(old);
    CPU_FREE(set);
    return rc;
}

static int parse_tid(const char *s, pid_t *tid)
{
    char *end = NULL;
    long value = strtol(s, &end, 10);

    if (!end || *end || value <= 0 || value > 2147483647L)
        return -1;
    *tid = (pid_t)value;
    return 0;
}

int main(int argc, char **argv)
{
    pid_t tid;

    if (argc >= 3 && parse_tid(argv[2], &tid)) {
        fprintf(stderr, "invalid tid\n");
        return 2;
    }
    if (argc == 3 && !strcmp(argv[1], "get"))
        return get_cmd(tid);
    if (argc == 4 && !strcmp(argv[1], "set-ext"))
        return set_ext_cmd(tid, argv[3]);
    if (argc == 6 && !strcmp(argv[1], "restore"))
        return restore_cmd(tid, argv[3], argv[4], argv[5]);
    fprintf(stderr, "usage: %s get <tid> | set-ext <tid> <cpu-list> | restore <tid> <policy> <priority> <cpu-list>\n", argv[0]);
    return 2;
}
