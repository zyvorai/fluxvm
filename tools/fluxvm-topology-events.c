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

struct topo_event {uint64_t timestamp_ns,vm_key,duration_ns;uint32_t event_type,tid,vcpu,cpu,from_cpu,to_cpu;};
struct ctx {uint64_t wanted;unsigned limit,seen;}; static volatile sig_atomic_t stop;
static void sig(int n){(void)n;stop=1;}
static const char *name(uint32_t t){switch(t){case 1:return"vcpu-migration";case 2:return"hardirq-long";case 3:return"softirq-long";case 4:return"vcpu-slice-long";default:return"unknown";}}
static int sample(void *opaque,void *data,size_t len){struct ctx *c=opaque;if(len<sizeof(struct topo_event))return 0;const struct topo_event *e=data;if(c->wanted&&e->vm_key!=c->wanted)return 0;printf("{\"timestamp_ns\":%llu,\"vm_key\":%llu,\"event_type\":%u,\"event\":\"%s\",\"tid\":%u,\"vcpu\":%u,\"cpu\":%u,\"from_cpu\":%u,\"to_cpu\":%u,\"duration_ns\":%llu}\n",(unsigned long long)e->timestamp_ns,(unsigned long long)e->vm_key,e->event_type,name(e->event_type),e->tid,e->vcpu,e->cpu,e->from_cpu,e->to_cpu,(unsigned long long)e->duration_ns);fflush(stdout);if(++c->seen>=c->limit)stop=1;return 0;}
static uint64_t ms(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return(uint64_t)t.tv_sec*1000ULL+(uint64_t)t.tv_nsec/1000000ULL;}
int main(int argc,char **argv){if(argc!=5){fprintf(stderr,"usage: %s <ringbuf-pin> <vm-key> <seconds> <limit>\n",argv[0]);return 2;}int fd=bpf_obj_get(argv[1]);if(fd<0){fprintf(stderr,"open %s: %s\n",argv[1],strerror(errno));return 1;}struct ctx c={.wanted=strtoull(argv[2],NULL,0),.limit=(unsigned)strtoul(argv[4],NULL,10)};if(!c.limit)c.limit=1;struct ring_buffer *rb=ring_buffer__new(fd,sample,&c,NULL);long e=libbpf_get_error(rb);if(e){fprintf(stderr,"ring buffer: %s\n",strerror((int)-e));close(fd);return 1;}signal(SIGINT,sig);signal(SIGTERM,sig);uint64_t end=ms()+(uint64_t)strtoul(argv[3],NULL,10)*1000ULL;while(!stop&&ms()<end){int r=ring_buffer__poll(rb,100);if(r==-EINTR)continue;if(r<0){fprintf(stderr,"poll: %d\n",r);ring_buffer__free(rb);close(fd);return 1;}}ring_buffer__free(rb);close(fd);return 0;}
