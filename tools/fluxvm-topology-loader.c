// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int join_path(char *out, size_t out_size, const char *dir, const char *name)
{
    int n = snprintf(out, out_size, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= out_size) {
        fprintf(stderr, "path too long: %s/%s\n", dir, name);
        return -1;
    }
    return 0;
}

static int mkdir_p(const char *path)
{
    char tmp[PATH_MAX]; size_t n=strlen(path); if(!n||n>=sizeof(tmp)) return -ENAMETOOLONG;
    memcpy(tmp,path,n+1); for(char *p=tmp+1;*p;p++){if(*p!='/')continue;*p='\0';if(mkdir(tmp,0755)&&errno!=EEXIST)return -errno;*p='/';}
    if (mkdir(tmp, 0755) && errno != EEXIST)
        return -errno;
    return 0;
}

static int remove_node(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
    (void)st; (void)type; (void)ftw;
    return remove(path);
}

static int rm_tree(const char *path)
{
    if (access(path, F_OK) != 0)
        return errno == ENOENT ? 0 : -errno;
    return nftw(path, remove_node, 32, FTW_DEPTH | FTW_PHYS);
}

static int pin_link(struct bpf_link *link,const char *path)
{
    long e=libbpf_get_error(link); if(e) return (int)e;
    int rc=bpf_link__pin(link,path); bpf_link__destroy(link); return rc;
}

static int attach_tp(struct bpf_object *obj,const char *prog,const char *cat,const char *event,const char *path,int required)
{
    struct bpf_program *p=bpf_object__find_program_by_name(obj,prog); if(!p)return -ENOENT;
    struct bpf_link *link=bpf_program__attach_tracepoint(p,cat,event); long e=libbpf_get_error(link);
    if(e){fprintf(stderr,"%s tracepoint %s/%s unavailable: %s\n",required?"required":"optional",cat,event,strerror((int)-e));return required?(int)e:0;}
    int rc=pin_link(link,path); if(rc)fprintf(stderr,"pin %s: %s\n",path,strerror(-rc)); return rc?rc:1;
}

static int load(const char *obj_path,const char *root)
{
    char maps[PATH_MAX],links[PATH_MAX];
    if(join_path(maps,sizeof(maps),root,"maps")||join_path(links,sizeof(links),root,"links"))return 1;
    if(mkdir_p(maps)||mkdir_p(links)){perror("mkdir topology pins");return 1;}
    char sentinel[PATH_MAX]; if(join_path(sentinel,sizeof(sentinel),maps,"topo_tracked_vcpus"))return 1;
    if(access(sentinel,F_OK)==0){printf("{\"ok\":true,\"already_loaded\":true,\"pin_root\":\"%s\"}\n",root);return 0;}
    struct bpf_object *obj=bpf_object__open_file(obj_path,NULL); long oe=libbpf_get_error(obj); if(oe){fprintf(stderr,"open %s: %s\n",obj_path,strerror((int)-oe));return 1;}
    int rc=bpf_object__load(obj); if(rc){fprintf(stderr,"load %s: %s\n",obj_path,strerror(-rc));bpf_object__close(obj);return 1;}
    rc=bpf_object__pin_maps(obj,maps); if(rc){fprintf(stderr,"pin maps: %s\n",strerror(-rc));bpf_object__close(obj);rm_tree(root);return 1;}
    struct {const char *prog,*cat,*event,*pin;int required;} a[]={
        {"fluxvm_topo_sched_switch","sched","sched_switch","sched_switch",1},
        {"fluxvm_topo_sched_migrate","sched","sched_migrate_task","sched_migrate",0},
        {"fluxvm_topo_irq_enter","irq","irq_handler_entry","irq_enter",0},
        {"fluxvm_topo_irq_exit","irq","irq_handler_exit","irq_exit",0},
        {"fluxvm_topo_softirq_enter","irq","softirq_entry","softirq_enter",0},
        {"fluxvm_topo_softirq_exit","irq","softirq_exit","softirq_exit",0},
    };
    unsigned attached=0; int result[6]={0}; char paths[6][PATH_MAX];
    for(size_t i=0;i<sizeof(a)/sizeof(a[0]);i++){if(join_path(paths[i],sizeof(paths[i]),links,a[i].pin)){bpf_object__close(obj);rm_tree(root);return 1;}result[i]=attach_tp(obj,a[i].prog,a[i].cat,a[i].event,paths[i],a[i].required);if(result[i]<0){bpf_object__close(obj);rm_tree(root);return 1;}if(result[i]>0)attached++;}
    /* IRQ duration needs entry+exit as a pair. Do not leave a half-probe alive. */
    if ((result[2] > 0) != (result[3] > 0)) { if(result[2]>0)unlink(paths[2]); if(result[3]>0)unlink(paths[3]); attached--; fprintf(stderr,"hardirq tracepoint pair incomplete; disabled\n"); }
    if ((result[4] > 0) != (result[5] > 0)) { if(result[4]>0)unlink(paths[4]); if(result[5]>0)unlink(paths[5]); attached--; fprintf(stderr,"softirq tracepoint pair incomplete; disabled\n"); }
    bpf_object__close(obj); printf("{\"ok\":true,\"attached_links\":%u,\"pin_root\":\"%s\"}\n",attached,root); return 0;
}

int main(int argc,char **argv)
{
    if(argc<3){fprintf(stderr,"usage: %s load <object> <pin-root> | unload <pin-root> | status <pin-root>\n",argv[0]);return 2;}
    if(strcmp(argv[1],"load")==0){if(argc!=4)return 2;return load(argv[2],argv[3]);}
    if(strcmp(argv[1],"unload")==0){if(argc!=3)return 2;return rm_tree(argv[2])?1:0;}
    if(strcmp(argv[1],"status")==0){if(argc!=3)return 2;char maps[PATH_MAX],p[PATH_MAX];if(join_path(maps,sizeof(maps),argv[2],"maps")||join_path(p,sizeof(p),maps,"topo_tracked_vcpus"))return 1;printf("{\"loaded\":%s}\n",access(p,F_OK)==0?"true":"false");return 0;}
    fprintf(stderr,"unknown command %s\n",argv[1]); return 2;
}
