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

struct mem_event {
    uint64_t timestamp_ns;
    uint64_t vm_key;
    uint64_t duration_ns;
    uint64_t arg0;
    uint32_t tid;
    uint32_t cpu;
    uint32_t event_type;
    uint32_t reserved;
};

struct context {
    uint64_t wanted;
    unsigned int limit;
    unsigned int seen;
};

static volatile sig_atomic_t stop;
static void on_signal(int signo) { (void)signo; stop = 1; }

static const char *event_name(uint32_t t)
{
    switch (t) {
    case 1: return "page-fault";
    case 2: return "direct-reclaim";
    case 3: return "first-kvm-entry";
    case 4: return "first-vhost-activity";
    default: return "unknown";
    }
}

static int sample(void *opaque, void *data, size_t len)
{
    struct context *ctx = opaque;
    if (len < sizeof(struct mem_event))
        return 0;
    const struct mem_event *e = data;
    if (ctx->wanted && e->vm_key != ctx->wanted)
        return 0;
    printf("{\"timestamp_ns\":%llu,\"vm_key\":%llu,\"event_type\":%u,\"event\":\"%s\",\"tid\":%u,\"cpu\":%u,\"duration_ns\":%llu,\"arg0\":%llu}\n",
           (unsigned long long)e->timestamp_ns,
           (unsigned long long)e->vm_key,
           e->event_type, event_name(e->event_type), e->tid, e->cpu,
           (unsigned long long)e->duration_ns,
           (unsigned long long)e->arg0);
    fflush(stdout);
    ctx->seen++;
    if (ctx->limit && ctx->seen >= ctx->limit)
        stop = 1;
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
    if (argc != 5) {
        fprintf(stderr, "usage: %s <ringbuf-pin> <vm-key> <seconds> <limit>\n", argv[0]);
        return 2;
    }
    const char *pin = argv[1];
    struct context ctx = {
        .wanted = strtoull(argv[2], NULL, 0),
        .limit = (unsigned int)strtoul(argv[4], NULL, 10),
    };
    unsigned int seconds = (unsigned int)strtoul(argv[3], NULL, 10);
    int fd = bpf_obj_get(pin);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", pin, strerror(errno));
        return 1;
    }
    struct ring_buffer *rb = ring_buffer__new(fd, sample, &ctx, NULL);
    long rb_err = libbpf_get_error(rb);
    if (rb_err) {
        fprintf(stderr, "ring buffer: %s\n", strerror((int)-rb_err));
        close(fd);
        return 1;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    uint64_t deadline = monotonic_ms() + (uint64_t)seconds * 1000ULL;
    while (!stop && monotonic_ms() < deadline) {
        int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
            continue;
        if (err < 0) {
            fprintf(stderr, "ring buffer poll: %d\n", err);
            ring_buffer__free(rb);
            close(fd);
            return 1;
        }
    }
    ring_buffer__free(rb);
    close(fd);
    return 0;
}
