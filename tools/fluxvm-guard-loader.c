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

static int mkdir_p(const char *path) {
    char tmp[PATH_MAX]; size_t len=strnlen(path,sizeof(tmp)-1);
    if (!len || len>=sizeof(tmp)-1) return -EINVAL;
    memcpy(tmp,path,len); tmp[len]='\0'; if (tmp[len-1]=='/') tmp[len-1]='\0';
    for (char *p=tmp+1;*p;p++) if (*p=='/') { *p='\0'; if (mkdir(tmp,0755)&&errno!=EEXIST) return -errno; *p='/'; }
    if (mkdir(tmp,0755)&&errno!=EEXIST) return -errno;
    return 0;
}
static int unlink_cb(const char *path,const struct stat *st,int type,struct FTW *ftw){(void)st;(void)type;(void)ftw;return remove(path);}
static int unload_root(const char *root){if(!root||root[0]!='/')return -EINVAL;if(access(root,F_OK)!=0)return errno==ENOENT?0:-errno;return nftw(root,unlink_cb,32,FTW_DEPTH|FTW_PHYS)==0?0:-errno;}
static void sanitize(char *s){for(;*s;s++) if(*s=='/'||*s==':')*s='_';}

static int bpf_lsm_enabled(void) {
    FILE *f=fopen("/sys/kernel/security/lsm","r");
    if (!f) return 1; /* actual load/attach remains authoritative */
    char buf[4096]={0}; size_t n=fread(buf,1,sizeof(buf)-1,f); fclose(f); buf[n]='\0';
    return strstr(buf,"bpf")!=NULL;
}

static int load_object(const char *object_path,const char *root) {
    if (!bpf_lsm_enabled()) {
        fprintf(stderr,"BPF LSM is not enabled; ensure kernel CONFIG_BPF_LSM=y and 'bpf' is present in /sys/kernel/security/lsm\n");
        return -ENOTSUP;
    }
    char map_dir[PATH_MAX],link_dir[PATH_MAX],link_path[PATH_MAX];
    if (snprintf(map_dir,sizeof(map_dir),"%s/maps",root)>=(int)sizeof(map_dir) ||
        snprintf(link_dir,sizeof(link_dir),"%s/links",root)>=(int)sizeof(link_dir)) return -ENAMETOOLONG;
    int err=mkdir_p(map_dir); if(err)return err; err=mkdir_p(link_dir); if(err)return err;
    struct bpf_object *obj=bpf_object__open_file(object_path,NULL);
    if (!obj) { int e=errno?errno:EINVAL; fprintf(stderr,"open %s: %s\n",object_path,strerror(e)); return -e; }
    long lerr=libbpf_get_error(obj); if(lerr){fprintf(stderr,"open %s: %s\n",object_path,strerror((int)-lerr));return (int)lerr;}
    if ((err=bpf_object__load(obj))!=0){fprintf(stderr,"load %s: %s\n",object_path,strerror(-err));goto out;}
    if ((err=bpf_object__pin_maps(obj,map_dir))!=0){fprintf(stderr,"pin maps: %s\n",strerror(-err));goto out;}
    struct bpf_link **links=NULL; size_t n=0,cap=0; struct bpf_program *prog;
    bpf_object__for_each_program(prog,obj) {
        struct bpf_link *link=bpf_program__attach_lsm(prog);
        if (!link) { int e=errno?errno:EINVAL; fprintf(stderr,"attach %s: %s\n",bpf_program__name(prog),strerror(e)); err=-e; goto links_out; }
        lerr=libbpf_get_error(link);
        if(lerr){fprintf(stderr,"attach %s: %s\n",bpf_program__name(prog),strerror((int)-lerr));err=(int)lerr;goto links_out;}
        if(n==cap){size_t next=cap?cap*2:4;void *p=realloc(links,next*sizeof(*links));if(!p){bpf_link__destroy(link);err=-ENOMEM;goto links_out;}links=p;cap=next;}
        links[n++]=link; char name[256]; snprintf(name,sizeof(name),"%s",bpf_program__name(prog)); sanitize(name);
        if(snprintf(link_path,sizeof(link_path),"%s/%s",link_dir,name)>=(int)sizeof(link_path)){err=-ENAMETOOLONG;goto links_out;}
        unlink(link_path); if((err=bpf_link__pin(link,link_path))!=0){fprintf(stderr,"pin link %s: %s\n",link_path,strerror(-err));goto links_out;}
    }
    if(!n){err=-ENOTSUP;fprintf(stderr,"no BPF-LSM programs attached\n");}
    else printf("FluxVM VMM Guard loaded: %s -> %s (%zu LSM links)\n",object_path,root,n);
links_out:
    for(size_t i=0;i<n;i++) bpf_link__destroy(links[i]);
    free(links);
out:
    if(err) unload_root(root);
    bpf_object__close(obj);
    return err;
}

int main(int argc,char **argv){
    if(argc==3 && strcmp(argv[1],"--unload")==0) return unload_root(argv[2])?1:0;
    if(argc!=4 || strcmp(argv[1],"--load")!=0){fprintf(stderr,"usage: %s --load <guard.bpf.o> <pin-root>\n       %s --unload <pin-root>\n",argv[0],argv[0]);return 2;}
    unload_root(argv[3]); return load_object(argv[2],argv[3])?1:0;
}
