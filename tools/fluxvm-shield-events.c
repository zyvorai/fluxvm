// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
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

struct shield_event {
    uint64_t timestamp_ns;
    uint32_t generation;
    uint32_t ifindex;
    uint32_t reason;
    uint32_t action;
    uint8_t family;
    uint8_t class_id;
    uint8_t protocol;
    uint8_t reserved0;
    uint8_t source[16];
    uint8_t destination[16];
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t bytes;
};

static volatile sig_atomic_t stop;
struct context { unsigned long limit, seen; };
static void on_signal(int signo) { (void)signo; stop = 1; }
static const char *reason(uint32_t v) {
    switch (v) { case 0:return "pass"; case 1:return "explicit-deny"; case 2:return "syn-rate";
    case 3:return "udp-rate"; case 4:return "icmp-rate"; case 5:return "other-rate";
    case 6:return "bucket-exhausted"; case 7:return "malformed"; default:return "unknown"; }
}
static const char *action(uint32_t v) { return v==1?"drop":v==2?"audit":"pass"; }
static int sample(void *ctxp, void *data, size_t size) {
    struct context *ctx = ctxp;
    if (size < sizeof(struct shield_event)) return 0;
    const struct shield_event *e = data;
    char src[INET6_ADDRSTRLEN] = "?", dst[INET6_ADDRSTRLEN] = "?";
    int af = e->family == 4 ? AF_INET : AF_INET6;
    (void)inet_ntop(af, e->source, src, sizeof(src));
    (void)inet_ntop(af, e->destination, dst, sizeof(dst));
    printf("{\"timestamp_ns\":%llu,\"generation\":%u,\"ifindex\":%u,\"reason\":\"%s\",\"action\":\"%s\",\"family\":%u,\"class\":%u,\"protocol\":%u,\"source\":\"%s\",\"destination\":\"%s\",\"source_port\":%u,\"destination_port\":%u,\"bytes\":%u}\n",
           (unsigned long long)e->timestamp_ns, e->generation, e->ifindex, reason(e->reason), action(e->action),
           e->family, e->class_id, e->protocol, src, dst, e->source_port, e->destination_port, e->bytes);
    fflush(stdout);
    if (++ctx->seen >= ctx->limit) stop = 1;
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: %s MAP_PIN SECONDS LIMIT\n", argv[0]); return 2; }
    unsigned long seconds = strtoul(argv[2], NULL, 10), limit = strtoul(argv[3], NULL, 10);
    if (!seconds || !limit) return 2;
    int fd = bpf_obj_get(argv[1]); if (fd < 0) { perror("bpf_obj_get"); return 3; }
    struct context ctx = {.limit=limit};
    struct ring_buffer *rb = ring_buffer__new(fd, sample, &ctx, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed\n"); close(fd); return 3; }
    signal(SIGINT, on_signal); signal(SIGTERM, on_signal);
    time_t until = time(NULL) + (time_t)seconds;
    while (!stop && time(NULL) < until) { int rc = ring_buffer__poll(rb, 100); if (rc < 0 && rc != -EINTR) break; }
    ring_buffer__free(rb); close(fd); return 0;
}
