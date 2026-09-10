// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct flight_event {
    uint64_t timestamp_ns;
    uint64_t vm_key;
    uint64_t duration_ns;
    uint64_t arg0;
    uint64_t arg1;
    uint32_t tid;
    uint32_t cpu;
    uint32_t event_type;
    uint32_t reserved;
};
_Static_assert(sizeof(struct flight_event) == 56, "flight event ABI");

struct reader_ctx {
    uint64_t vm_key;
    size_t seen;
    size_t limit;
};

static volatile sig_atomic_t stop;
static void on_signal(int sig) { (void)sig; stop = 1; }

static const char *event_name(uint32_t type)
{
    switch (type) {
    case 1: return "kvm-exit";
    case 2: return "scheduler-delay";
    case 3: return "block-complete";
    case 4: return "vhost-queue";
    case 5: return "vhost-wakeup";
    default: return "unknown";
    }
}

static int on_event(void *opaque, void *data, size_t size)
{
    struct reader_ctx *ctx = opaque;
    if (size < sizeof(struct flight_event)) return 0;
    const struct flight_event *e = data;
    if (ctx->vm_key && e->vm_key != ctx->vm_key) return 0;
    printf("{\"timestamp_ns\":%" PRIu64 ",\"vm_key\":%" PRIu64
           ",\"event_type\":%u,\"event\":\"%s\",\"tid\":%u,\"cpu\":%u"
           ",\"duration_ns\":%" PRIu64 ",\"arg0\":%" PRIu64 ",\"arg1\":%" PRIu64 "}\n",
           e->timestamp_ns, e->vm_key, e->event_type, event_name(e->event_type),
           e->tid, e->cpu, e->duration_ns, e->arg0, e->arg1);
    fflush(stdout);
    ctx->seen++;
    if (ctx->limit && ctx->seen >= ctx->limit) stop = 1;
    return 0;
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s --map <flight_events-pin> --vm-key <u64> [--seconds N] [--limit N]\n",
        argv0);
}

int main(int argc, char **argv)
{
    const char *map = NULL;
    uint64_t vm_key = 0;
    unsigned seconds = 5;
    size_t limit = 128;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--map") && i + 1 < argc) map = argv[++i];
        else if (!strcmp(argv[i], "--vm-key") && i + 1 < argc) vm_key = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) seconds = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--limit") && i + 1 < argc) limit = (size_t)strtoull(argv[++i], NULL, 10);
        else { usage(argv[0]); return 2; }
    }
    if (!map || !vm_key || seconds > 3600 || limit > 100000) {
        usage(argv[0]); return 2;
    }

    int fd = bpf_obj_get(map);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", map, strerror(errno)); return 1; }
    struct reader_ctx ctx = {.vm_key = vm_key, .limit = limit};
    struct ring_buffer *rb = ring_buffer__new(fd, on_event, &ctx, NULL);
    long err = libbpf_get_error(rb);
    if (err) { fprintf(stderr, "ring_buffer__new: %s\n", strerror((int)-err)); close(fd); return 1; }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    uint64_t deadline = monotonic_ms() + (uint64_t)seconds * 1000ULL;
    while (!stop && monotonic_ms() < deadline) {
        int rc = ring_buffer__poll(rb, 100);
        if (rc == -EINTR) continue;
        if (rc < 0) { fprintf(stderr, "ring buffer poll: %s\n", strerror(-rc)); break; }
    }
    ring_buffer__free(rb);
    close(fd);
    return 0;
}
