// SETUP ONLY. No observer execution. Compile-time IO seams exist only in fixtures.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <linux/magic.h>
#include <linux/falloc.h>
#include <dirent.h>
#include "setup-observer-data.h"
#define TOP "age30-qualification"
#define PARENT "age30-qualification-age30-8bbc3a9d-r1"
#define OBSERVER "cgroup-observe-v1"
#define READ_BOUND 4096U
#define REPORT_BOUND 16384U
#define EVIDENCE_BOUND 65536U
_Static_assert(sizeof(observer_bytes)>0&&sizeof(observer_bytes)<=262144U,"observer bound");
#ifndef SETUP_FIXTURE
static int io_root(void){return open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);}
static int io_open(int p,const char *n,int flags,bool cross){struct open_how h={.flags=(uint64_t)(unsigned)flags,.mode=(flags&O_CREAT)?0600U:0U,.resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS};if(!cross)h.resolve|=RESOLVE_NO_XDEV;return (int)syscall(SYS_openat2,p,n,&h,sizeof(h));}
static int io_statx(int fd,struct statx *x){return (int)syscall(SYS_statx,fd,"",AT_EMPTY_PATH|AT_NO_AUTOMOUNT,STATX_BASIC_STATS|STATX_MNT_ID,x);}
#define IO_ROOT io_root
#define IO_OPEN io_open
#define IO_STAT fstat
#define IO_STATX io_statx
#define IO_FS fstatfs
#define IO_MKDIR mkdirat
#define IO_READ read
#define IO_WRITE write
#define IO_SYNC fsync
#define IO_ALLOC(fd) fallocate((fd),FALLOC_FL_KEEP_SIZE,0,(off_t)REPORT_BOUND)
#define IO_MODE fchmod
#define IO_DENTS(fd,b,n) syscall(SYS_getdents64,(fd),(b),(n))
#define IO_CLOCK clock_gettime
#endif
struct id {dev_t dev;ino_t ino;uint64_t mount;mode_t mode;};
struct node {int fd,parent;const char *name;struct id id;bool cross;};
struct state {struct node nodes[16];unsigned count;int root,var,lib,sys,fs,cg,top,evidence,bin,journal,observer,parent,reports[3];const char *phase,*error;int number;bool complete;size_t written;uint64_t started;};
struct dent {uint64_t ino;int64_t off;unsigned short len;unsigned char type;char name[];};
static bool eligible(int argc,bool linux_os,bool x64,uid_t u,uid_t eu,gid_t g,gid_t eg){return argc==1&&linux_os&&x64&&u==0&&eu==0&&g==0&&eg==0;}
// Save errno at the operation, once. Semantic failures always have no errno.
static bool fail(struct state *s,const char *why,int number){if(!s->error){s->error=why;s->number=number;}return false;}
#define REQUIRE(s,p,why) do {if(!(p))return fail((s),(why),0);} while(0)
#define SYSCHECK(s,p,why) do {if((p)<0){int saved=errno;return fail((s),(why),saved);}} while(0)
static bool identify(struct state *s,int fd,struct id *id,bool directory,mode_t exact){
 struct stat st;struct statx x;
 SYSCHECK(s,IO_STAT(fd,&st),"fstat");SYSCHECK(s,IO_STATX(fd,&x),"statx");
 REQUIRE(s,(x.stx_mask&STATX_MNT_ID)&&st.st_uid==0&&st.st_gid==0&&!(st.st_mode&07022U),"custody");
 REQUIRE(s,directory?S_ISDIR(st.st_mode):(S_ISREG(st.st_mode)&&st.st_nlink==1),"type_or_links");
 REQUIRE(s,!exact||(st.st_mode&07777U)==exact,"mode");
 id->dev=st.st_dev;id->ino=st.st_ino;id->mount=x.stx_mnt_id;id->mode=st.st_mode;return true;
}
static bool equal(const struct id *a,const struct id *b){return a->dev==b->dev&&a->ino==b->ino&&a->mount==b->mount&&a->mode==b->mode;}
static int add(struct state *s,int parent,const char *name,bool dir,bool crossing,int flags,mode_t mode){
 if(s->count>=16U){(void)fail(s,"node_capacity",0);return -1;}
 int fd=parent<0?IO_ROOT():IO_OPEN(s->nodes[parent].fd,name,flags|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC|(dir?O_DIRECTORY:0),crossing);
 if(fd<0){int saved=errno;(void)fail(s,"openat2",saved);return -1;}
 unsigned index=s->count++;struct node *n=&s->nodes[index];n->fd=fd;n->parent=parent;n->name=name;n->cross=crossing;
 if(!identify(s,fd,&n->id,dir,mode))return -1;
 if(parent>=0&&!crossing&&(n->id.dev!=s->nodes[parent].id.dev||n->id.mount!=s->nodes[parent].id.mount)){(void)fail(s,"cross_device",0);return -1;}
 return (int)index;
}
static bool stable(struct state *s){
 struct timespec t;SYSCHECK(s,IO_CLOCK(CLOCK_MONOTONIC,&t),"clock");
 REQUIRE(s,t.tv_sec>=0,"clock_value");uint64_t now=(uint64_t)t.tv_sec*1000U+(uint64_t)t.tv_nsec/1000000U;
 REQUIRE(s,now>=s->started&&now-s->started<10000U,"deadline_refusal");
 for(unsigned i=0;i<s->count;i++){
  struct node *n=&s->nodes[i];struct id held,named;bool dir=S_ISDIR(n->id.mode);
  if(!identify(s,n->fd,&held,dir,n->id.mode&07777U))return false;REQUIRE(s,equal(&held,&n->id),"held_identity");
  int fd=n->parent<0?IO_ROOT():IO_OPEN(s->nodes[n->parent].fd,n->name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|(dir?O_DIRECTORY:0),n->cross);
  if(fd<0){int saved=errno;return fail(s,"name_open",saved);}bool ok=identify(s,fd,&named,dir,n->id.mode&07777U);
  int closed=close(fd),saved=errno;if(!ok)return false;if(closed<0)return fail(s,"close",saved);REQUIRE(s,equal(&named,&n->id),"name_identity");
 }return true;
}
static bool absent(struct state *s,int dir,const char *name){
 int fd=IO_OPEN(s->nodes[dir].fd,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,false);int saved=errno;
 if(fd>=0){(void)close(fd);return fail(s,"preexisting",0);}REQUIRE(s,saved==ENOENT,"preexisting_or_unsafe");return true;
}
static bool read_value(struct state *s,int dir,const char *name,char out[READ_BOUND+1U],size_t *len){
 int fd=IO_OPEN(s->nodes[dir].fd,name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,false);if(fd<0){int saved=errno;return fail(s,"read_open",saved);}
 struct id id,after;bool ok=identify(s,fd,&id,false,0);ssize_t n=-1;char extra;
 if(ok&&(id.dev!=s->nodes[dir].id.dev||id.mount!=s->nodes[dir].id.mount))ok=fail(s,"read_mount",0);
 if(ok){n=IO_READ(fd,out,READ_BOUND+1U);if(n<0){int saved=errno;ok=fail(s,"read",saved);}else if((size_t)n>READ_BOUND)ok=fail(s,"read_bound",0);}
 if(ok){ssize_t tail=IO_READ(fd,&extra,1);if(tail<0){int saved=errno;ok=fail(s,"read_tail",saved);}else if(tail!=0)ok=fail(s,"read_trailing",0);}
 if(ok)ok=identify(s,fd,&after,false,0);if(ok&&!equal(&id,&after))ok=fail(s,"read_identity",0);
 int closed=close(fd),saved=errno;if(ok&&closed<0)ok=fail(s,"close",saved);if(!ok)return false;
 *len=(size_t)n;out[*len]=0;REQUIRE(s,!memchr(out,0,*len),"read_nul");return true;
}
static bool controllers(const char *b,bool exact){
 unsigned mask=0;const char *p=b;while(*p){while(*p==' '||*p=='\n')p++;if(!*p)break;const char *end=p;while(*end&&*end!=' '&&*end!='\n')end++;size_t n=(size_t)(end-p);unsigned bit=n==3U&&!memcmp(p,"cpu",3)?1U:n==6U&&!memcmp(p,"memory",6)?2U:n==4U&&!memcmp(p,"pids",4)?4U:8U;if((mask&bit)&&bit!=8U)return false;mask|=bit;p=end;}return exact?mask==7U:(mask&7U)==7U;
}
static bool no_children(struct state *s,int dir){
 _Alignas(uint64_t) unsigned char buf[READ_BOUND],extra[READ_BOUND];SYSCHECK(s,lseek(s->nodes[dir].fd,0,SEEK_SET),"dir_seek");
 long n=IO_DENTS(s->nodes[dir].fd,buf,sizeof(buf));if(n<0){int saved=errno;return fail(s,"getdents",saved);}REQUIRE(s,(unsigned long)n<=sizeof(buf),"directory_bound");
 long tail=IO_DENTS(s->nodes[dir].fd,extra,sizeof(extra));if(tail<0){int saved=errno;return fail(s,"getdents_tail",saved);}REQUIRE(s,tail==0,"directory_bound");
 size_t at=0;while(at<(size_t)n){size_t fixed=offsetof(struct dent,name);REQUIRE(s,(size_t)n-at>=fixed+1U,"directory_encoding");struct dent *d=(struct dent *)(void *)(buf+at);REQUIRE(s,d->len>=fixed+1U&&d->len<=(size_t)n-at&&memchr(d->name,0,(size_t)d->len-fixed),"directory_encoding");
  REQUIRE(s,(!strcmp(d->name,".")||!strcmp(d->name,".."))?d->type==DT_DIR:d->type==DT_REG,"unexpected_child");at+=d->len;
 }return true;
}
static bool parent_check(struct state *s,int dir,bool enabled){
 char b[READ_BOUND+1U];size_t n;struct statfs fs;
 SYSCHECK(s,IO_FS(s->nodes[dir].fd,&fs),"fstatfs");REQUIRE(s,fs.f_type==CGROUP2_SUPER_MAGIC,"not_cgroup2");
 if(!read_value(s,dir,"cgroup.type",b,&n))return false;REQUIRE(s,!strcmp(b,"domain\n"),"not_domain");
 if(!read_value(s,dir,"cgroup.controllers",b,&n))return false;REQUIRE(s,controllers(b,false),"missing_controllers");
 if(!read_value(s,dir,"cgroup.subtree_control",b,&n))return false;REQUIRE(s,enabled?controllers(b,dir==s->parent):n==0U,"subtree_set");
 if(dir==s->cg)return true; // Root may host processes and unrelated children: never enumerate them.
 if(!read_value(s,dir,"cgroup.procs",b,&n))return false;REQUIRE(s,n==0U,"occupied");
 if(!read_value(s,dir,"cgroup.events",b,&n))return false;REQUIRE(s,!strcmp(b,"populated 0\nfrozen 0\n"),"population_or_events");
 return no_children(s,dir);
}
static int mkdir_node(struct state *s,int parent,const char *name){
 if(!stable(s))return -1;if(IO_MKDIR(s->nodes[parent].fd,name,0700)<0){int saved=errno;(void)fail(s,"mkdir_exclusive",saved);return -1;}
 return add(s,parent,name,true,false,O_RDONLY,0700);
}
static bool sync_node(struct state *s,int n){SYSCHECK(s,IO_SYNC(s->nodes[n].fd),"fsync");return true;}
static bool write_once(struct state *s,int fd,const void *bytes,size_t n){
 ssize_t got=IO_WRITE(fd,bytes,n);if(got<0){int saved=errno;return fail(s,"write",saved);}REQUIRE(s,got==(ssize_t)n,"short_write");return true;
}
static bool report(struct state *s,unsigned which,bool complete){
 REQUIRE(s,which<3U&&s->reports[which]>=0,"report_unavailable");int node=s->reports[which];struct stat st;
 SYSCHECK(s,IO_STAT(s->nodes[node].fd,&st),"report_stat");REQUIRE(s,st.st_size==0,"report_not_empty");
 char b[8192];size_t used=0;int n=snprintf(b,sizeof(b),"{\"version\":1,\"status\":\"UNKNOWN\",\"admission\":false,\"qualified\":false,\"assumptionsVerified\":false,\"setupComplete\":%s,\"phase\":\"%s\",\"error\":\"%s\",\"errorClass\":\"%s\",\"errorErrno\":%d,\"observerSize\":%zu,\"observerSha256\":\"%s\",\"cgroupDurability\":\"RUNTIME_ONLY\",\"nodes\":[",complete?"true":"false",s->phase,s->error?s->error:"none",s->error?(s->number?"SYSCALL":"NO_ERRNO"):"NONE",s->number,sizeof(observer_bytes),observer_sha256);
 REQUIRE(s,n>0&&(size_t)n<sizeof(b),"report_bound");used=(size_t)n;
 for(unsigned i=0;i<s->count;i++){struct node *v=&s->nodes[i];n=snprintf(b+used,sizeof(b)-used,"%s{\"name\":\"%s\",\"dev\":%llu,\"ino\":%llu,\"mount\":%llu,\"mode\":%u}",i?",":"",v->name,(unsigned long long)v->id.dev,(unsigned long long)v->id.ino,(unsigned long long)v->id.mount,(unsigned)(v->id.mode&07777U));REQUIRE(s,n>0&&(size_t)n<sizeof(b)-used,"report_bound");used+=(size_t)n;}
 REQUIRE(s,used+4U<sizeof(b)&&used+4U<=REPORT_BOUND&&s->written<=EVIDENCE_BOUND-(used+4U),"report_bound");memcpy(b+used,"]}\n",3);used+=3U;
 if(!stable(s))return false;if(!write_once(s,s->nodes[node].fd,b,used))return false;s->written+=used;return sync_node(s,node)&&sync_node(s,s->journal);
}
static bool perform(struct state *s){
 struct timespec now;SYSCHECK(s,IO_CLOCK(CLOCK_MONOTONIC,&now),"clock");REQUIRE(s,now.tv_sec>=0,"clock_value");s->started=(uint64_t)now.tv_sec*1000U+(uint64_t)now.tv_nsec/1000000U;
 s->phase="preflight";
 s->root=add(s,-1,"/",true,true,O_RDONLY,0);if(s->root<0)return false;
 s->var=add(s,s->root,"var",true,true,O_RDONLY,0);if(s->var<0)return false;
 s->lib=add(s,s->var,"lib",true,true,O_RDONLY,0);if(s->lib<0)return false;
 s->sys=add(s,s->root,"sys",true,true,O_RDONLY,0);if(s->sys<0)return false;
 s->fs=add(s,s->sys,"fs",true,true,O_RDONLY,0);if(s->fs<0)return false;
 s->cg=add(s,s->fs,"cgroup",true,true,O_RDONLY,0);if(s->cg<0)return false;
 if(!parent_check(s,s->cg,true)||!absent(s,s->lib,TOP)||!absent(s,s->cg,PARENT)||!stable(s))return false;
 s->phase="reserve";s->top=mkdir_node(s,s->lib,TOP);if(s->top<0)return false;
 s->evidence=mkdir_node(s,s->top,"evidence");if(s->evidence<0)return false;
 s->bin=mkdir_node(s,s->top,"bin");if(s->bin<0)return false;
 s->journal=mkdir_node(s,s->top,"setup-v1");if(s->journal<0)return false;
 const char *const names[]={"start.json","inventory.json","result.json"};
 for(unsigned i=0;i<3U;i++){
  s->reports[i]=add(s,s->journal,names[i],false,false,O_RDWR|O_CREAT|O_EXCL,0600);if(s->reports[i]<0)return false;
  SYSCHECK(s,IO_ALLOC(s->nodes[s->reports[i]].fd),"reservation");if(!sync_node(s,s->reports[i]))return false;
 }
 if(!sync_node(s,s->journal)||!sync_node(s,s->evidence)||!sync_node(s,s->bin)||!sync_node(s,s->top)||!sync_node(s,s->lib))return false;
 s->phase="start";if(!report(s,0,false))return false;
 s->phase="install";if(!stable(s))return false;
 s->observer=add(s,s->bin,OBSERVER,false,false,O_RDWR|O_CREAT|O_EXCL,0600);if(s->observer<0)return false;
 if(!write_once(s,s->nodes[s->observer].fd,observer_bytes,sizeof(observer_bytes)))return false;
 SYSCHECK(s,lseek(s->nodes[s->observer].fd,0,SEEK_SET),"observer_seek");
 unsigned char copy[sizeof(observer_bytes)+1U];ssize_t n=IO_READ(s->nodes[s->observer].fd,copy,sizeof(copy));if(n<0){int saved=errno;return fail(s,"observer_read",saved);}
 REQUIRE(s,n==(ssize_t)sizeof(observer_bytes)&&!memcmp(copy,observer_bytes,sizeof(observer_bytes)),"observer_comparison");
 struct stat st;SYSCHECK(s,IO_STAT(s->nodes[s->observer].fd,&st),"observer_stat");REQUIRE(s,st.st_size==(off_t)sizeof(observer_bytes),"observer_size");
 if(!stable(s))return false;SYSCHECK(s,IO_MODE(s->nodes[s->observer].fd,0500),"observer_mode");
 struct id executable; if(!identify(s,s->nodes[s->observer].fd,&executable,false,0500))return false;
 REQUIRE(s,executable.dev==s->nodes[s->observer].id.dev&&executable.ino==s->nodes[s->observer].id.ino&&executable.mount==s->nodes[s->observer].id.mount,"observer_identity");s->nodes[s->observer].id=executable;
 if(!sync_node(s,s->observer)||!sync_node(s,s->bin)||!sync_node(s,s->top)||!sync_node(s,s->lib))return false;
 s->phase="custody_durable";if(!report(s,1,false)||!stable(s)||!parent_check(s,s->cg,true)||!absent(s,s->cg,PARENT))return false;
 s->phase="cgroup_create";s->parent=mkdir_node(s,s->cg,PARENT);if(s->parent<0)return false;
 if(!parent_check(s,s->parent,false)||!stable(s)||!parent_check(s,s->cg,true))return false;
 s->phase="enable";
 int fd=IO_OPEN(s->nodes[s->parent].fd,"cgroup.subtree_control",O_WRONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,false);if(fd<0){int saved=errno;return fail(s,"control_open",saved);}
 struct id id;bool ok=identify(s,fd,&id,false,0);
 if(ok&&(id.dev!=s->nodes[s->parent].id.dev||id.mount!=s->nodes[s->parent].id.mount))ok=fail(s,"control_identity",0);
 if(ok){int named=IO_OPEN(s->nodes[s->parent].fd,"cgroup.subtree_control",O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,false);if(named<0){int saved=errno;ok=fail(s,"control_name_open",saved);}else{struct id current;ok=identify(s,named,&current,false,0);if(ok&&!equal(&id,&current))ok=fail(s,"control_name_identity",0);int closed=close(named),saved=errno;if(ok&&closed<0)ok=fail(s,"close",saved);}}
 if(ok)ok=write_once(s,fd,"+cpu +memory +pids\n",19U);
 int closed=close(fd),saved=errno;if(ok&&closed<0)ok=fail(s,"close",saved);if(!ok)return false;
 if(!stable(s)||!parent_check(s,s->parent,true)||!parent_check(s,s->cg,true))return false;
 s->phase="complete";return true;
}
static int setup(void){
 struct state s;memset(&s,0,sizeof(s));s.phase="initial";s.parent=-1;for(unsigned i=0;i<3U;i++)s.reports[i]=-1;
 s.complete=perform(&s);
 // A terminal receipt is the only permitted effect after failure. No retry of any report.
 if(s.reports[2]>=0){bool complete=s.complete;(void)report(&s,2,complete);}
 for(unsigned i=0;i<s.count;i++)(void)close(s.nodes[i].fd);
 return 2;
}
#ifndef SETUP_FIXTURE
int main(int argc,char **argv){
 (void)argv;struct utsname u;bool x64=uname(&u)==0&&!strcmp(u.sysname,"Linux")&&!strcmp(u.machine,"x86_64");
 if(!eligible(argc,true,x64,getuid(),geteuid(),getgid(),getegid()))return 2;
 if(syscall(SYS_close_range,3U,UINT_MAX,0U)||clearenv())return 2;(void)umask(0077);
 return setup();
}
#endif
