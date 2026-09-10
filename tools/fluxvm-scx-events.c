// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct fluxvm_scx_event {
    uint64_t timestamp_ns;
    uint64_t vm_key;
    uint32_t tid;
    uint32_t cpu;
    uint64_t queue_delay_ns;
    uint64_t latency_target_ns;
    uint32_t weight;
    uint32_t event_type;
};

struct context {
    uint64_t vm_key;
    unsigned limit;
    unsigned seen;
};

static volatile sig_atomic_t stop_requested;

static void on_signal(int sig)
{
    (void)sig;
    stop_requested = 1;
}

static int on_event(void *ctx, void *data, size_t size)
{
    struct context *c = ctx;
    const struct fluxvm_scx_event *e = data;

    if (size < sizeof(*e) || e->vm_key != c->vm_key)
        return 0;
    if (c->seen >= c->limit)
        return 0;
    printf("{\"timestamp_ns\":%llu,\"vm_key\":%llu,\"event\":\"queue-latency\",\"event_type\":%u,\"tid\":%u,\"cpu\":%u,\"queue_delay_ns\":%llu,\"latency_target_ns\":%llu,\"weight\":%u}\n",
           (unsigned long long)e->timestamp_ns,
           (unsigned long long)e->vm_key,
           e->event_type,
           e->tid,
           e->cpu,
           (unsigned long long)e->queue_delay_ns,
           (unsigned long long)e->latency_target_ns,
           e->weight);
    fflush(stdout);
    c->seen++;
    if (c->seen >= c->limit)
        stop_requested = 1;
    return 0;
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

int main(int argc, char **argv)
{
    char path[4096];
    char *end = NULL;
    unsigned long long vm_key;
    unsigned long seconds, limit;
    struct ring_buffer *rb;
    struct context ctx;
    uint64_t deadline;
    int fd, rc = 0;

    if (argc != 5) {
        fprintf(stderr, "usage: %s <pin-root> <vm-key> <seconds> <limit>\n", argv[0]);
        return 2;
    }
    errno = 0;
    vm_key = strtoull(argv[2], &end, 10);
    if (errno || !end || *end)
        return 2;
    seconds = strtoul(argv[3], &end, 10);
    if (!end || *end || seconds > 86400)
        return 2;
    limit = strtoul(argv[4], &end, 10);
    if (!end || *end || !limit || limit > 1000000)
        return 2;

    int path_n = snprintf(path, sizeof(path), "%s/maps/scx_events", argv[1]);
    if (path_n < 0 || (size_t)path_n >= sizeof(path)) {
        fprintf(stderr, "pin-root path too long\n");
        return 2;
    }
    fd = bpf_obj_get(path);
    if (fd < 0) {
        fprintf(stderr, "opening %s: %s\n", path, strerror(errno));
        return 3;
    }
    ctx.vm_key = (uint64_t)vm_key;
    ctx.limit = (unsigned)limit;
    ctx.seen = 0;
    rb = ring_buffer__new(fd, on_event, &ctx, NULL);
    if (!rb || libbpf_get_error(rb)) {
        fprintf(stderr, "ring_buffer__new failed\n");
        close(fd);
        return 4;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    deadline = monotonic_ms() + seconds * 1000ULL;
    while (!stop_requested && monotonic_ms() < deadline) {
        rc = ring_buffer__poll(rb, 100);
        if (rc == -EINTR) {
            rc = 0;
            continue;
        }
        if (rc < 0)
            break;
    }
    ring_buffer__free(rb);
    close(fd);
    return rc < 0 ? 5 : 0;
}
