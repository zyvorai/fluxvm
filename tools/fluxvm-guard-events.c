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

struct guard_event { uint64_t timestamp_ns,vm_key,object_id,aux; uint32_t pid,action,decision,reserved; };
static volatile sig_atomic_t stop;
static uint64_t wanted_vm; static unsigned long limit=128,seen;
static void on_signal(int sig){(void)sig;stop=1;}
static const char *action_name(uint32_t v){switch(v){case 1:return"exec";case 2:return"wx-mprotect";case 3:return"device-open";case 4:return"write-open";default:return"unknown";}}
static const char *decision_name(uint32_t v){switch(v){case 0:return"allow";case 1:return"audit";case 2:return"deny";default:return"unknown";}}
static int event_cb(void *ctx,void *data,size_t size){(void)ctx;if(size<sizeof(struct guard_event))return 0;const struct guard_event *e=data;if(wanted_vm&&e->vm_key!=wanted_vm)return 0;printf("{\"timestamp_ns\":%llu,\"vm_key\":%llu,\"pid\":%u,\"action\":\"%s\",\"decision\":\"%s\",\"object_id\":%llu,\"aux\":%llu}\n",(unsigned long long)e->timestamp_ns,(unsigned long long)e->vm_key,e->pid,action_name(e->action),decision_name(e->decision),(unsigned long long)e->object_id,(unsigned long long)e->aux);fflush(stdout);if(++seen>=limit)stop=1;return 0;}
int main(int argc,char **argv){
    if(argc<2||argc>5){fprintf(stderr,"usage: %s <ringbuf-pin> [vm-key] [seconds] [limit]\n",argv[0]);return 2;}
    if(argc>2) wanted_vm=strtoull(argv[2],NULL,0);
    unsigned seconds=argc>3?(unsigned)strtoul(argv[3],NULL,10):5;
    if(argc>4) limit=strtoul(argv[4],NULL,10);
    if(!limit) limit=1;
    int fd=bpf_obj_get(argv[1]);if(fd<0){perror("bpf_obj_get");return 1;}struct ring_buffer *rb=ring_buffer__new(fd,event_cb,NULL,NULL);if(!rb){perror("ring_buffer__new");close(fd);return 1;}
    signal(SIGINT,on_signal);signal(SIGTERM,on_signal);time_t end=time(NULL)+seconds;
    while(!stop&&time(NULL)<end){int rc=ring_buffer__poll(rb,200);if(rc<0&&rc!=-EINTR){fprintf(stderr,"ring_buffer__poll: %s\n",strerror(-rc));ring_buffer__free(rb);close(fd);return 1;}}
    ring_buffer__free(rb);close(fd);return 0;
}
