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

struct afxdp_event {
    uint64_t timestamp_ns;
    uint64_t vm_key;
    uint32_t ifindex;
    uint32_t queue_id;
    uint32_t bytes;
    uint32_t key;
};

static volatile sig_atomic_t stop_requested;
static size_t seen, limit_count;
static uint64_t deadline_ns;
static uint64_t mono_ns(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000ULL+(uint64_t)ts.tv_nsec;}
static void sig_handler(int s){(void)s;stop_requested=1;}
static int on_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct afxdp_event)) return 0;
    const struct afxdp_event *e=data;
    printf("{\"timestamp_ns\":%llu,\"vm_key\":%llu,\"ifindex\":%u,\"queue\":%u,\"bytes\":%u,\"key\":%u}\n",
           (unsigned long long)e->timestamp_ns,(unsigned long long)e->vm_key,e->ifindex,e->queue_id,e->bytes,e->key);
    fflush(stdout); seen++; if (limit_count && seen>=limit_count) stop_requested=1; return 0;
}
int main(int argc,char **argv)
{
    if(argc<2||argc>4){fprintf(stderr,"usage: %s <pin-root> [seconds] [limit]\n",argv[0]);return 2;}
    unsigned seconds=argc>=3?(unsigned)strtoul(argv[2],NULL,10):5;limit_count=argc>=4?(size_t)strtoull(argv[3],NULL,10):128;
    char path[4096];snprintf(path,sizeof(path),"%s/maps/afxdp_events",argv[1]);
    int fd=bpf_obj_get(path);if(fd<0){fprintf(stderr,"open %s: %s\n",path,strerror(errno));return 3;}
    struct ring_buffer *rb=ring_buffer__new(fd,on_event,NULL,NULL);if(!rb){fprintf(stderr,"ring_buffer__new failed\n");close(fd);return 4;}
    signal(SIGINT,sig_handler);signal(SIGTERM,sig_handler);deadline_ns=mono_ns()+(uint64_t)seconds*1000000000ULL;
    while(!stop_requested&&mono_ns()<deadline_ns){int r=ring_buffer__poll(rb,100);if(r<0&&r!=-EINTR){fprintf(stderr,"ring poll: %d\n",r);break;}}
    ring_buffer__free(rb);close(fd);return 0;
}
