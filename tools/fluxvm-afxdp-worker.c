// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <xdp/xsk.h>

#ifndef XDP_PKT_CONTD
#define XDP_PKT_CONTD (1U << 0)
#endif

#define MAX_QUEUES 64U
#define FRAME_SIZE 4096U
#define FRAME_COUNT 4096U
#define HALF_FRAMES (FRAME_COUNT/2U)
#define RING_SIZE 2048U
#define DEFAULT_BATCH 64U
#define PENDING_MAX FRAME_COUNT

struct runtime_stat {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t dropped_packets;
    uint64_t tx_ring_full;
    uint64_t fill_deferred;
    uint64_t poll_wakeups;
    uint64_t multibuf_drops;
    uint64_t last_update_ns;
    uint32_t zero_copy;
    uint32_t worker_pid;
};
_Static_assert(sizeof(struct runtime_stat) == 88, "runtime ABI");

struct side {
    const char *ifname;
    uint32_t slot;
    uint32_t queue;
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct runtime_stat stat;
    bool dropping_multibuf;
};

struct bridge {
    void *area;
    size_t area_len;
    struct xsk_umem *umem;
    struct side a, b;
    uint64_t pending_a[PENDING_MAX];
    uint64_t pending_b[PENDING_MAX];
    uint32_t pending_a_n, pending_b_n;
    int xsks_fd, gate_fd, runtime_fd;
    uint32_t batch;
};

static volatile sig_atomic_t stop_requested;
static void on_signal(int sig) { (void)sig; stop_requested = 1; }
static uint64_t mono_ns(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return (uint64_t)ts.tv_sec*1000000000ULL+(uint64_t)ts.tv_nsec; }
static uint32_t map_key(const struct side *s) { return s->slot * MAX_QUEUES + s->queue; }
static bool origin_a(uint64_t addr) { return xsk_umem__extract_addr(addr) < (uint64_t)HALF_FRAMES * FRAME_SIZE; }

static int refill_one(struct xsk_ring_prod *fill, uint64_t addr)
{
    uint32_t idx;
    if (xsk_ring_prod__reserve(fill, 1, &idx) != 1) return -ENOSPC;
    *xsk_ring_prod__fill_addr(fill, idx) = xsk_umem__extract_addr(addr);
    xsk_ring_prod__submit(fill, 1);
    return 0;
}

static void pend(struct bridge *br, uint64_t addr)
{
    uint64_t *v; uint32_t *n;
    if (origin_a(addr)) { v=br->pending_a; n=&br->pending_a_n; }
    else { v=br->pending_b; n=&br->pending_b_n; }
    if (*n < PENDING_MAX) v[(*n)++] = xsk_umem__extract_addr(addr);
}

static void flush_pending_vec(struct xsk_ring_prod *fill, uint64_t *v, uint32_t *n, struct runtime_stat *st)
{
    while (*n) {
        uint64_t addr = v[*n - 1];
        if (refill_one(fill, addr)) { st->fill_deferred++; break; }
        (*n)--;
    }
}

static void flush_pending(struct bridge *br)
{
    flush_pending_vec(&br->a.fill, br->pending_a, &br->pending_a_n, &br->a.stat);
    flush_pending_vec(&br->b.fill, br->pending_b, &br->pending_b_n, &br->b.stat);
}

static void drain_completions(struct bridge *br, struct side *s)
{
    uint32_t idx;
    unsigned n = xsk_ring_cons__peek(&s->comp, br->batch, &idx);
    for (unsigned i=0; i<n; i++) pend(br, *xsk_ring_cons__comp_addr(&s->comp, idx+i));
    if (n) xsk_ring_cons__release(&s->comp, n);
}

static bool socket_zero_copy(struct xsk_socket *xsk)
{
    struct xdp_options o = {};
    socklen_t n = sizeof(o);
    if (getsockopt(xsk_socket__fd(xsk), SOL_XDP, XDP_OPTIONS, &o, &n)) return false;
    return (o.flags & XDP_OPTIONS_ZEROCOPY) != 0;
}

static void kick_tx(struct side *s)
{
    if (xsk_ring_prod__needs_wakeup(&s->tx))
        (void)sendto(xsk_socket__fd(s->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static void bridge_rx(struct bridge *br, struct side *src, struct side *dst)
{
    uint32_t idx;
    unsigned n = xsk_ring_cons__peek(&src->rx, br->batch, &idx);
    if (!n) return;
    unsigned submitted = 0;
    for (unsigned i=0; i<n; i++) {
        const struct xdp_desc *r = xsk_ring_cons__rx_desc(&src->rx, idx+i);
        src->stat.rx_packets++; src->stat.rx_bytes += r->len;
        bool contd = (r->options & XDP_PKT_CONTD) != 0;
        if (src->dropping_multibuf || contd) {
            src->stat.dropped_packets++; src->stat.multibuf_drops++;
            pend(br, r->addr);
            src->dropping_multibuf = contd;
            continue;
        }
        uint32_t txi;
        if (xsk_ring_prod__reserve(&dst->tx, 1, &txi) != 1) {
            src->stat.dropped_packets++; src->stat.tx_ring_full++;
            pend(br, r->addr);
            continue;
        }
        struct xdp_desc *t = xsk_ring_prod__tx_desc(&dst->tx, txi);
        t->addr = r->addr; t->len = r->len; t->options = 0;
        xsk_ring_prod__submit(&dst->tx, 1);
        dst->stat.tx_packets++; dst->stat.tx_bytes += r->len; submitted++;
    }
    xsk_ring_cons__release(&src->rx, n);
    if (submitted) kick_tx(dst);
}

static int open_map(const char *root, const char *name)
{
    char path[4096]; snprintf(path,sizeof(path),"%s/maps/%s",root,name);
    int fd=bpf_obj_get(path); if(fd<0) fprintf(stderr,"open %s: %s\n",path,strerror(errno)); return fd;
}

static int update_u32(int fd, uint32_t key, uint32_t value)
{
    return bpf_map_update_elem(fd,&key,&value,BPF_ANY) ? -errno : 0;
}

static void write_runtime(struct bridge *br)
{
    struct side *sides[]={&br->a,&br->b};
    for (size_t i=0;i<2;i++) {
        struct side *s=sides[i]; uint32_t key=map_key(s);
        s->stat.last_update_ns=mono_ns(); s->stat.worker_pid=(uint32_t)getpid();
        (void)bpf_map_update_elem(br->runtime_fd,&key,&s->stat,BPF_ANY);
    }
}

static int seed_fill(struct xsk_ring_prod *fill, uint32_t first, uint32_t count)
{
    uint32_t idx;
    if (xsk_ring_prod__reserve(fill,count,&idx) != count) return -ENOSPC;
    for (uint32_t i=0;i<count;i++) *xsk_ring_prod__fill_addr(fill,idx+i)=(uint64_t)(first+i)*FRAME_SIZE;
    xsk_ring_prod__submit(fill,count); return 0;
}

static int xsk_create_pair(struct bridge *br, const char *mode)
{
    if (posix_memalign(&br->area, getpagesize(), (size_t)FRAME_COUNT*FRAME_SIZE)) return -ENOMEM;
    br->area_len=(size_t)FRAME_COUNT*FRAME_SIZE; memset(br->area,0,br->area_len);
    struct xsk_umem_config uc={.fill_size=RING_SIZE,.comp_size=RING_SIZE,.frame_size=FRAME_SIZE,.frame_headroom=0,.flags=0};
    int err=xsk_umem__create(&br->umem,br->area,br->area_len,&br->a.fill,&br->a.comp,&uc); if(err) return err;
    uint16_t bind_flags=XDP_USE_NEED_WAKEUP;
    if(!strcmp(mode,"copy")) bind_flags|=XDP_COPY;
    else if(!strcmp(mode,"zerocopy")) bind_flags|=XDP_ZEROCOPY;
    else if(strcmp(mode,"auto")) return -EINVAL;
    struct xsk_socket_config sc={.rx_size=RING_SIZE,.tx_size=RING_SIZE,.libxdp_flags=XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,.xdp_flags=0,.bind_flags=bind_flags};
    err=xsk_socket__create(&br->a.xsk,br->a.ifname,br->a.queue,br->umem,&br->a.rx,&br->a.tx,&sc); if(err) return err;
    err=xsk_socket__create_shared(&br->b.xsk,br->b.ifname,br->b.queue,br->umem,&br->b.rx,&br->b.tx,&br->b.fill,&br->b.comp,&sc); if(err) return err;
    br->a.stat.zero_copy=socket_zero_copy(br->a.xsk); br->b.stat.zero_copy=socket_zero_copy(br->b.xsk);
    if(!strcmp(mode,"zerocopy") && (!br->a.stat.zero_copy || !br->b.stat.zero_copy)) return -EOPNOTSUPP;
    if ((err=seed_fill(&br->a.fill,0,HALF_FRAMES))) return err;
    if ((err=seed_fill(&br->b.fill,HALF_FRAMES,HALF_FRAMES))) return err;
    return 0;
}

static void cleanup(struct bridge *br)
{
    uint32_t zero=0,ka=map_key(&br->a),kb=map_key(&br->b);
    if(br->gate_fd>=0){(void)update_u32(br->gate_fd,ka,zero);(void)update_u32(br->gate_fd,kb,zero);}
    if(br->xsks_fd>=0){(void)bpf_map_delete_elem(br->xsks_fd,&ka);(void)bpf_map_delete_elem(br->xsks_fd,&kb);}
    if (br->a.xsk)
        xsk_socket__delete(br->a.xsk);
    if (br->b.xsk)
        xsk_socket__delete(br->b.xsk);
    if (br->umem)
        xsk_umem__delete(br->umem);
    free(br->area);
    if (br->xsks_fd >= 0)
        close(br->xsks_fd);
    if (br->gate_fd >= 0)
        close(br->gate_fd);
    if (br->runtime_fd >= 0)
        close(br->runtime_fd);
}

static int run_bridge(struct bridge *br, const char *pin_root, const char *mode)
{
    br->xsks_fd=open_map(pin_root,"afxdp_xsks");br->gate_fd=open_map(pin_root,"afxdp_queue_enabled");br->runtime_fd=open_map(pin_root,"afxdp_runtime");
    if(br->xsks_fd<0||br->gate_fd<0||br->runtime_fd<0)return 3;
    int err=xsk_create_pair(br,mode);if(err){fprintf(stderr,"AF_XDP create: %s\n",strerror(-err));return 4;}
    uint32_t ka=map_key(&br->a),kb=map_key(&br->b);int fda=xsk_socket__fd(br->a.xsk),fdb=xsk_socket__fd(br->b.xsk);
    if(bpf_map_update_elem(br->xsks_fd,&ka,&fda,BPF_ANY)||bpf_map_update_elem(br->xsks_fd,&kb,&fdb,BPF_ANY)){fprintf(stderr,"XSKMAP update: %s\n",strerror(errno));return 5;}
    uint32_t one=1;if(update_u32(br->gate_fd,ka,one)||update_u32(br->gate_fd,kb,one)){fprintf(stderr,"queue gate update failed\n");return 5;}
    signal(SIGINT,on_signal);signal(SIGTERM,on_signal);write_runtime(br);
    fprintf(stderr,"FluxVM AF_XDP bridge %s/q%u <-> %s/q%u mode=%s zc=%u/%u pid=%d\n",br->a.ifname,br->a.queue,br->b.ifname,br->b.queue,mode,br->a.stat.zero_copy,br->b.stat.zero_copy,getpid());
    struct pollfd pfds[2]={{.fd=fda,.events=POLLIN},{.fd=fdb,.events=POLLIN}};uint64_t last=mono_ns();
    while(!stop_requested){
        drain_completions(br,&br->a);drain_completions(br,&br->b);flush_pending(br);
        bridge_rx(br,&br->a,&br->b);bridge_rx(br,&br->b,&br->a);
        if(xsk_ring_prod__needs_wakeup(&br->a.fill)||xsk_ring_prod__needs_wakeup(&br->b.fill)){
            int r=poll(pfds,2,20);if(r>0){br->a.stat.poll_wakeups++;br->b.stat.poll_wakeups++;}
        }
        uint64_t now=mono_ns();if(now-last>=1000000000ULL){write_runtime(br);last=now;}
    }
    write_runtime(br);return 0;
}

static void usage(const char *p)
{
    fprintf(stderr,"usage: %s <pin-root> <iface-a> <queue-a> <iface-b> <queue-b> <auto|copy|zerocopy> [batch]\n",p);
}

int main(int argc,char **argv)
{
    if(argc<7||argc>8){usage(argv[0]);return 2;}
    char *ea=NULL,*eb=NULL;unsigned long qa=strtoul(argv[3],&ea,10),qb=strtoul(argv[5],&eb,10);
    if(!ea||*ea||!eb||*eb||qa>=MAX_QUEUES||qb>=MAX_QUEUES){fprintf(stderr,"invalid queue\n");return 2;}
    struct bridge br={.a={.ifname=argv[2],.slot=0,.queue=(uint32_t)qa},.b={.ifname=argv[4],.slot=1,.queue=(uint32_t)qb},.xsks_fd=-1,.gate_fd=-1,.runtime_fd=-1,.batch=DEFAULT_BATCH};
    if(argc==8){unsigned long n=strtoul(argv[7],NULL,10);if(n<1||n>256){fprintf(stderr,"batch must be 1..256\n");return 2;}br.batch=(uint32_t)n;}
    int rc=run_bridge(&br,argv[1],argv[6]);cleanup(&br);return rc;
}
