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
#include <time.h>
#include <unistd.h>

struct tcp_event { uint64_t timestamp_ns,vm_key;uint32_t ifindex,event_type;uint8_t family,direction,reserved0[2],guest[16],remote[16];uint16_t guest_port,remote_port;uint32_t sequence,acknowledgement;uint64_t duration_ns; };
static volatile sig_atomic_t stop; struct context{unsigned long limit,seen;};
static void on_signal(int s){(void)s;stop=1;}
static const char *event_name(uint32_t t){switch(t){case 1:return"syn";case 2:return"established";case 3:return"retransmit";case 4:return"rtt";case 5:return"rst";case 6:return"fin";default:return"unknown";}}
static int sample(void *p,void *data,size_t size){struct context *c=p;if(size<sizeof(struct tcp_event))return 0;const struct tcp_event *e=data;char guest[INET6_ADDRSTRLEN]="?",remote[INET6_ADDRSTRLEN]="?";int af=e->family==4?AF_INET:AF_INET6;(void)inet_ntop(af,e->guest,guest,sizeof(guest));(void)inet_ntop(af,e->remote,remote,sizeof(remote));printf("{\"timestamp_ns\":%llu,\"vm_key\":%llu,\"ifindex\":%u,\"event\":\"%s\",\"family\":%u,\"direction\":\"%s\",\"guest\":\"%s\",\"remote\":\"%s\",\"guest_port\":%u,\"remote_port\":%u,\"sequence\":%u,\"acknowledgement\":%u,\"duration_ns\":%llu}\n",(unsigned long long)e->timestamp_ns,(unsigned long long)e->vm_key,e->ifindex,event_name(e->event_type),e->family,e->direction==1?"guest-to-remote":"remote-to-guest",guest,remote,e->guest_port,e->remote_port,e->sequence,e->acknowledgement,(unsigned long long)e->duration_ns);fflush(stdout);if(++c->seen>=c->limit)stop=1;return 0;}
int main(int argc,char **argv){if(argc!=4){fprintf(stderr,"usage: %s MAP_PIN SECONDS LIMIT\n",argv[0]);return 2;}unsigned long sec=strtoul(argv[2],NULL,10),lim=strtoul(argv[3],NULL,10);if(!sec||!lim)return 2;int fd=bpf_obj_get(argv[1]);if(fd<0){perror("bpf_obj_get");return 3;}struct context c={.limit=lim};struct ring_buffer *rb=ring_buffer__new(fd,sample,&c,NULL);if(!rb){close(fd);return 3;}signal(SIGINT,on_signal);signal(SIGTERM,on_signal);time_t until=time(NULL)+(time_t)sec;while(!stop&&time(NULL)<until){int rc=ring_buffer__poll(rb,100);if(rc<0&&rc!=-EINTR)break;}ring_buffer__free(rb);close(fd);return 0;}
