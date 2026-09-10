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
struct quic_event { uint64_t timestamp_ns; uint32_t service_id, backend_id, ifindex, event_type, cid_hash; uint16_t sport, dport; uint8_t family, cid_len, pad[2]; };
static volatile sig_atomic_t stop;
static unsigned limit = 128, count;
static const char *label(uint32_t t) { switch (t) { case 1:return "select"; case 2:return "affinity-hit"; case 3:return "reselect"; case 4:return "parse-error"; case 5:return "backend-miss"; case 6:return "non-quic"; default:return "unknown"; } }
static int event_cb(void *ctx, void *data, size_t len) { (void)ctx; if (len < sizeof(struct quic_event)) return 0; struct quic_event *e=data; printf("{\"timestamp_ns\":%llu,\"service_id\":%u,\"backend_id\":%u,\"ifindex\":%u,\"event\":\"%s\",\"cid_hash\":%u,\"sport\":%u,\"dport\":%u,\"family\":%u,\"cid_len\":%u}\n", (unsigned long long)e->timestamp_ns,e->service_id,e->backend_id,e->ifindex,label(e->event_type),e->cid_hash,e->sport,e->dport,e->family,e->cid_len); fflush(stdout); if (++count >= limit) stop=1; return 0; }
static void on_sig(int s) { (void)s; stop=1; }
int main(int argc, char **argv) { if (argc < 2 || argc > 4) { fprintf(stderr,"usage: %s <pin-root> [seconds] [limit]\n",argv[0]); return 2; } unsigned seconds=argc>2?(unsigned)strtoul(argv[2],NULL,10):5; limit=argc>3?(unsigned)strtoul(argv[3],NULL,10):128; if(!limit)limit=1; char p[4096]; int pn=snprintf(p,sizeof(p),"%s/maps/fluxvm_quic_events",argv[1]); if(pn<0||(size_t)pn>=sizeof(p)){fprintf(stderr,"pin-root path too long\n");return 2;} int fd=bpf_obj_get(p); if(fd<0){fprintf(stderr,"event ring unavailable (hardware-offload profile intentionally has no ringbuf): %s\n",strerror(errno));return 3;} struct ring_buffer *rb=ring_buffer__new(fd,event_cb,NULL,NULL); if(!rb){close(fd);return 4;} signal(SIGINT,on_sig); signal(SIGTERM,on_sig); time_t end=time(NULL)+seconds; while(!stop&&time(NULL)<end){int rc=ring_buffer__poll(rb,200);if(rc<0&&rc!=-EINTR){fprintf(stderr,"poll: %d\n",rc);break;}} ring_buffer__free(rb);close(fd);return 0; }
