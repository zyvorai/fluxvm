// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct tcp_config { uint64_t vm_key; uint32_t ifindex; uint32_t sample_rate; };

static int mkdir_p(const char *path)
{
    char buf[4096];
    size_t len = strlen(path);
    if (!len || len >= sizeof(buf))
        return -ENAMETOOLONG;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0755) && errno != EEXIST)
            return -errno;
        *p = '/';
    }
    if (mkdir(buf, 0755) && errno != EEXIST)
        return -errno;
    return 0;
}
static uint32_t legacy_handle(uint64_t vm_key) { return 0x8000u | (uint32_t)(vm_key & 0x7fffu); }
static int tcx_unsupported(int rc) { return rc == -EINVAL || rc == -EOPNOTSUPP || rc == -ENOTSUP; }

static int tcx_attach_pair(int ifindex, int out_fd, int in_fd, const char *pin_dir) {
    LIBBPF_OPTS(bpf_link_create_opts, opts);
    int ingress = bpf_link_create(out_fd, ifindex, BPF_TCX_INGRESS, &opts);
    if (ingress < 0) return ingress;
    int egress = bpf_link_create(in_fd, ifindex, BPF_TCX_EGRESS, &opts);
    if (egress < 0) { close(ingress); return egress; }
    char links[4096], in_pin[4096], out_pin[4096];
    if (snprintf(links,sizeof(links),"%s/links",pin_dir) >= (int)sizeof(links)) { close(ingress); close(egress); return -ENAMETOOLONG; }
    if (snprintf(in_pin,sizeof(in_pin),"%s/ingress",links) >= (int)sizeof(in_pin)) { close(ingress); close(egress); return -ENAMETOOLONG; }
    if (snprintf(out_pin,sizeof(out_pin),"%s/egress",links) >= (int)sizeof(out_pin)) { close(ingress); close(egress); return -ENAMETOOLONG; }
    int rc = mkdir_p(links);
    if (!rc && bpf_obj_pin(ingress, in_pin))
        rc = -errno;
    if (!rc && bpf_obj_pin(egress, out_pin))
        rc = -errno;
    if (rc) {
        unlink(in_pin);
        unlink(out_pin);
        close(ingress);
        close(egress);
        return rc;
    }
    close(ingress); close(egress); return 0;
}

static int tc_attach_one(int ifindex, enum bpf_tc_attach_point point, int prog_fd, uint32_t handle) {
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex=ifindex, .attach_point=point);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle=handle, .priority=49152, .prog_fd=prog_fd);
    int rc=bpf_tc_hook_create(&hook); if(rc && rc!=-EEXIST) return rc;
    return bpf_tc_attach(&hook,&opts);
}
static void tc_detach_one(int ifindex, enum bpf_tc_attach_point point, uint32_t handle) {
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex=ifindex, .attach_point=point);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle=handle, .priority=49152);
    (void)bpf_tc_detach(&hook,&opts);
}

static int attach_cmd(const char *iface,const char *object,const char *pin_dir,uint64_t vm_key,uint32_t sample_rate) {
    int ifindex=if_nametoindex(iface); if(!ifindex){fprintf(stderr,"unknown interface %s\n",iface);return 2;}
    struct bpf_object *obj=bpf_object__open_file(object,NULL); long err=libbpf_get_error(obj); if(err){fprintf(stderr,"open: %s\n",strerror((int)-err));return 3;}
    if(bpf_object__load(obj)){fprintf(stderr,"load failed\n");bpf_object__close(obj);return 3;}
    struct bpf_program *out=bpf_object__find_program_by_name(obj,"fluxvm_tcp_out"), *in=bpf_object__find_program_by_name(obj,"fluxvm_tcp_in");
    struct bpf_map *cfg=bpf_object__find_map_by_name(obj,"fluxvm_tcp_cfg");
    if(!out||!in||!cfg){fprintf(stderr,"required TCP intelligence BPF objects missing\n");bpf_object__close(obj);return 3;}
    uint32_t zero=0; struct tcp_config value={.vm_key=vm_key,.ifindex=(uint32_t)ifindex,.sample_rate=sample_rate};
    if(bpf_map_update_elem(bpf_map__fd(cfg),&zero,&value,BPF_ANY)){perror("tcp cfg update");bpf_object__close(obj);return 3;}
    char maps[4096];snprintf(maps,sizeof(maps),"%s/maps",pin_dir);if(mkdir_p(maps)){bpf_object__close(obj);return 3;}
    if(bpf_object__pin_maps(obj,maps)){fprintf(stderr,"pin maps failed\n");bpf_object__close(obj);return 3;}
    int rc=tcx_attach_pair(ifindex,bpf_program__fd(out),bpf_program__fd(in),pin_dir);
    const char *mode="tcx"; uint32_t handle=legacy_handle(vm_key);
    if(rc<0){
        if(!tcx_unsupported(rc)){fprintf(stderr,"TCX attach failed without safe legacy fallback: %s\n",strerror(-rc));(void)bpf_object__unpin_maps(obj,maps);bpf_object__close(obj);return 4;}
        rc=tc_attach_one(ifindex,BPF_TC_INGRESS,bpf_program__fd(out),handle);
        if(!rc) rc=tc_attach_one(ifindex,BPF_TC_EGRESS,bpf_program__fd(in),handle);
        if(rc){tc_detach_one(ifindex,BPF_TC_INGRESS,handle);tc_detach_one(ifindex,BPF_TC_EGRESS,handle);(void)bpf_object__unpin_maps(obj,maps);bpf_object__close(obj);fprintf(stderr,"legacy TC attach failed: %s\n",strerror(-rc));return 4;}
        mode="tc";
    }
    printf("{\"attached\":true,\"ifindex\":%d,\"mode\":\"%s\",\"handle\":%u}\n",ifindex,mode,handle);
    bpf_object__close(obj);return 0;
}

static int detach_cmd(const char *iface,const char *pin_dir,uint64_t vm_key) {
    int ifindex=if_nametoindex(iface);if(!ifindex)return 2;char in_pin[4096],out_pin[4096];
    snprintf(in_pin,sizeof(in_pin),"%s/links/ingress",pin_dir);snprintf(out_pin,sizeof(out_pin),"%s/links/egress",pin_dir);
    int in_fd=bpf_obj_get(in_pin),out_fd=bpf_obj_get(out_pin);
    if(in_fd>=0||out_fd>=0){if(in_fd>=0){(void)bpf_link_detach(in_fd);close(in_fd);unlink(in_pin);}if(out_fd>=0){(void)bpf_link_detach(out_fd);close(out_fd);unlink(out_pin);}printf("{\"detached\":true,\"mode\":\"tcx\"}\n");return 0;}
    uint32_t handle=legacy_handle(vm_key);tc_detach_one(ifindex,BPF_TC_INGRESS,handle);tc_detach_one(ifindex,BPF_TC_EGRESS,handle);
    printf("{\"detached\":true,\"mode\":\"tc\",\"handle\":%u}\n",handle);return 0;
}
int main(int argc,char **argv){
    if(argc>=2&&!strcmp(argv[1],"attach")&&argc==7)return attach_cmd(argv[2],argv[3],argv[4],strtoull(argv[5],NULL,10),(uint32_t)strtoul(argv[6],NULL,10));
    if(argc>=2&&!strcmp(argv[1],"detach")&&argc==5)return detach_cmd(argv[2],argv[3],strtoull(argv[4],NULL,10));
    fprintf(stderr,"usage: %s attach IFACE OBJECT PIN_DIR VM_KEY SAMPLE_RATE | detach IFACE PIN_DIR VM_KEY\n",argv[0]);return 2;
}
