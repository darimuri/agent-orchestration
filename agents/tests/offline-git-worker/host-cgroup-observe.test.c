// Separate nonprivileged binary. cgroup filesystem/custody/root identities below
// are SIMULATED; openat2, regular-file exclusivity and IO use disposable fixtures.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <linux/falloc.h>
#include <sys/utsname.h>
#include <time.h>
static int t_root(void),t_open(int,const char *,int,bool),t_statx(int,struct statx *),t_stat(int,struct stat *),t_fs(int,struct statfs *),t_mkdir(int,const char *,mode_t),t_sync(int),t_alloc(int),t_self(unsigned,char *,size_t),t_uname(struct utsname *),t_clock(clockid_t,struct timespec *);
static ssize_t t_read(int,void *,size_t),t_write(int,const void *,size_t);
static long t_dents(int,void *,size_t);
#define OBSERVER_TEST 1
#define IO_ROOT t_root
#define IO_OPEN t_open
#define IO_STATX t_statx
#define IO_STAT t_stat
#define IO_FS t_fs
#define IO_MKDIR t_mkdir
#define IO_READ t_read
#define IO_WRITE t_write
#define IO_SYNC t_sync
#define IO_ALLOC t_alloc
#define IO_DENTS t_dents
#define IO_SELF t_self
#define IO_UNAME t_uname
#define IO_CLOCK t_clock
#include "host-cgroup-observe.c"

#define FD_MAX 1024U
static char fixture[PATH_MAX],path_for[FD_MAX][512],trace[32768];
static bool cg_fd[FD_MAX],failed,changed;
static unsigned scenario,event,fail_at,writes,mkdirs,cases;
static size_t trace_used;
static bool tick(void){event++;if(event==fail_at){failed=true;errno=EIO;return false;}return true;}
static void note(const char *kind,const char *name){int n=snprintf(trace+trace_used,sizeof(trace)-trace_used,"%s:%s\n",kind,name);assert(n>0&&(size_t)n<sizeof(trace)-trace_used);trace_used+=(size_t)n;}
static void register_fd(int fd,int parent,const char *name){if(fd<0)return;assert((unsigned)fd<FD_MAX);char prefix[512];memcpy(prefix,parent>=0?path_for[parent]:"",parent>=0?strlen(path_for[parent])+1U:1U);int n=snprintf(path_for[fd],sizeof(path_for[fd]),"%s%s%s",prefix,parent>=0?"/":"",name);assert(n>=0&&(size_t)n<sizeof(path_for[fd]));cg_fd[fd]=(parent>=0&&cg_fd[parent])||!strcmp(name,"cgroup");}
static void put_at(int dir,const char *name,const char *value){int fd=openat(dir,name,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);assert(fd>=0);size_t n=strlen(value);assert(write(fd,value,n)==(ssize_t)n);assert(close(fd)==0);}
static void leaf_files(int dir){
 const char *const names[]={"cgroup.type","cgroup.events","cgroup.procs","cpu.stat","memory.current","memory.events","pids.current", "cpu.max","cpu.max.burst","memory.max","memory.swap.max","memory.oom.group","pids.max"};
 const char *const text[]={"domain\n","populated 0\nfrozen 0\n","","usage_usec 0\n","0\n","low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n","0\n", "max 100000\n","0\n","max\n","max\n","0\n","max\n"};
 for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++)put_at(dir,names[i],text[i]);
}
static int t_root(void){int fd=open(fixture,O_RDONLY|O_DIRECTORY|O_CLOEXEC);register_fd(fd,-1,"");return fd;}
static int t_open(int dir,const char *name,int flags,bool crossing){
 if(scenario==16U){errno=ENOSYS;return -1;}
 if((flags&O_CREAT)&&!tick())return -1;
 struct open_how h={.flags=(uint64_t)(unsigned)flags,.mode=(flags&O_CREAT)?0600U:0U,.resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS};if(!crossing)h.resolve|=RESOLVE_NO_XDEV;
 int fd=(int)syscall(SYS_openat2,dir,name,&h,sizeof(h));register_fd(fd,dir,name);return fd;
}
static int t_stat(int fd,struct stat *s){int r=fstat(fd,s);if(!r){s->st_uid=scenario==9U?10001U:0U;s->st_gid=scenario==31U?10001U:0U;if(scenario==28U)s->st_nlink=2;}return r;}
static int t_statx(int fd,struct statx *s){
 if(scenario==17U){errno=ENOSYS;return -1;}
 int r=(int)syscall(SYS_statx,fd,"",AT_EMPTY_PATH|AT_NO_AUTOMOUNT,STATX_BASIC_STATS|STATX_MNT_ID,s);
 if(!r&&changed&&cg_fd[fd])s->stx_mnt_id++;return r;
}
static int t_fs(int fd,struct statfs *s){int r=fstatfs(fd,s);if(!r&&cg_fd[fd])s->f_type=scenario==11U?TMPFS_MAGIC:CGROUP2_SUPER_MAGIC;return r;}
static int t_mkdir(int dir,const char *name,mode_t mode){
 assert(mode==0700);assert(!strcmp(name,RUN_ID)||!strcmp(name,LEAF));note("mkdir",name);mkdirs++;
 if(!tick())return -1;int r=mkdirat(dir,name,mode);
 if(!r&&!strcmp(name,LEAF)){int fd=openat(dir,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(fd>=0);leaf_files(fd);if(scenario>=25U&&scenario<=27U){assert(renameat(fd,"memory.max",fd,"retained-memory.max")==0);if(scenario==26U)assert(mkfifoat(fd,"memory.max",0600)==0);if(scenario==27U)assert(symlinkat("retained-memory.max",fd,"memory.max")==0);}assert(close(fd)==0);}return r;
}
static ssize_t t_read(int fd,void *b,size_t n){if(!tick())return -1;return read(fd,b,scenario==32U&&n>1U?1U:n);}
static ssize_t t_write(int fd,const void *b,size_t n){
 bool control=cg_fd[fd];
 if(control){assert(!failed);assert(writes<6U);const char *const golden_names[]={"cpu.max","cpu.max.burst","memory.max","memory.swap.max","memory.oom.group","pids.max"};
  const char *const golden_values[]={"20000 100000\n","0\n","536870912\n","0\n","1\n","8\n"};
  const char *name=strrchr(path_for[fd],'/');assert(name&&strstr(path_for[fd],"/" LEAF "/"));name++;
  assert(!strcmp(name,golden_names[writes])&&n==strlen(golden_values[writes])&&!memcmp(b,golden_values[writes],n));note("write",name);writes++;
 }
 if(!tick())return -1;
 if((scenario==22U&&control)||(scenario==23U&&!control)){failed=true;return write(fd,b,n-1U);}
 // cgroupfs replaces a control value; ordinary fixture files need explicit truncation.
 if(control){assert(ftruncate(fd,0)==0);assert(lseek(fd,0,SEEK_SET)==0);}
 ssize_t result;
 if(scenario==14U&&control){const char bad[]="invalid\n";assert(write(fd,bad,sizeof(bad)-1U)==(ssize_t)(sizeof(bad)-1U));result=(ssize_t)n;}
 else result=write(fd,b,n);
 if(control&&scenario==12U)changed=true;
 if(control&&scenario==13U){int leaf=openat(fd,".",O_RDONLY|O_DIRECTORY);assert(leaf<0);char full[PATH_MAX];int len=snprintf(full,sizeof(full),"%s/sys/fs/cgroup/" PARENT "/" LEAF,fixture);assert(len>0&&(size_t)len<sizeof(full));leaf=open(full,O_RDONLY|O_DIRECTORY);assert(leaf>=0);put_at(leaf,"cgroup.procs","123\n");put_at(leaf,"cgroup.events","populated 1\nfrozen 0\n");assert(close(leaf)==0);}
 return result;
}
static int t_sync(int fd){if(scenario==30U&&strstr(path_for[fd],"/start.json"))_exit(91);if(!tick())return -1;return fsync(fd);}
static int t_alloc(int fd){if(!tick()||scenario==18U){errno=ENOSPC;return -1;}return fallocate(fd,FALLOC_FL_KEEP_SIZE,0,(off_t)REPORT_BOUND);}
static long t_dents(int fd,void *b,size_t n){return syscall(SYS_getdents64,fd,b,n);}
static int t_self(unsigned which,char *out,size_t cap){
 if((scenario==19U||scenario==20U||scenario==21U)&&which==0U){size_t size=scenario==20U?4097U:4096U;assert(cap>=size);memset(out,'x',size);return (int)size;}
 if(scenario==21U){assert(cap>=4096U);memset(out,'x',4096U);return 4096;}
 static const char *const kind[]={"ipc","mnt","net","pid","user","uts"};if(which<2U){const char text[]="0 0 65536\n";memcpy(out,text,sizeof(text)-1U);return (int)(sizeof(text)-1U);}return snprintf(out,cap,"%s:[123]",kind[which-2U]);
}
static int t_uname(struct utsname *u){memset(u,0,sizeof(*u));strcpy(u->release,"fixture");strcpy(u->machine,"x86_64");return 0;}
static int t_clock(clockid_t clock,struct timespec *now){(void)clock;now->tv_sec=scenario==15U&&event>0U?11:0;now->tv_nsec=0;return 0;}
static void prepare(unsigned kind,unsigned fault){
 scenario=kind;fail_at=fault;event=0;writes=0;mkdirs=0;failed=false;changed=false;trace_used=0;trace[0]=0;memset(cg_fd,0,sizeof(cg_fd));memset(path_for,0,sizeof(path_for));
 assert(++cases<=512U);int n=snprintf(fixture,sizeof(fixture),"case-%04u",cases);assert(n>0&&(size_t)n<sizeof(fixture));assert(mkdir(fixture,0700)==0);
 int root=open(fixture,O_RDONLY|O_DIRECTORY);assert(root>=0);int dir=root;
 for(unsigned i=0;i<4U;i++){assert(mkdirat(dir,cg_parts[i],0700)==0);int next=openat(dir,cg_parts[i],O_RDONLY|O_DIRECTORY);assert(next>=0);if(dir!=root)assert(close(dir)==0);dir=next;}
 put_at(dir,"cgroup.type",kind==2U?"threaded\n":"domain\n");put_at(dir,"cgroup.controllers",kind==1U?"cpu memory\n":"cpu memory pids\n");put_at(dir,"cgroup.subtree_control",kind==29U?"cpu memory\n":"cpu memory pids\n");put_at(dir,"cgroup.events",kind==3U?"populated 1\n":"populated 0\nfrozen 0\n");put_at(dir,"cgroup.procs",kind==3U?"123\n":"");
 if(kind==4U)assert(mkdirat(dir,"unexpected",0700)==0);
 if(kind==7U){assert(mkdirat(dir,LEAF,0700)==0);int leaf=openat(dir,LEAF,O_RDONLY|O_DIRECTORY);assert(leaf>=0);leaf_files(leaf);assert(close(leaf)==0);}
 if(kind==10U)assert(fchmod(dir,0770)==0);assert(close(dir)==0);dir=root;
 for(unsigned i=0;i<4U;i++){assert(mkdirat(dir,evidence_parts[i],0700)==0);int next=openat(dir,evidence_parts[i],O_RDONLY|O_DIRECTORY);assert(next>=0);if(dir!=root)assert(close(dir)==0);dir=next;}
 if(kind==6U)assert(mkdirat(dir,RUN_ID,0700)==0);
 if(kind==8U)assert(mkfifoat(dir,RUN_ID,0600)==0);
 assert(close(dir)==0);
 if(kind==5U||kind==24U){assert(renameat(root,"sys/fs",root,"sys/original-fs")==0);if(kind==5U)assert(symlinkat("original-fs",root,"sys/fs")==0);else{int len=snprintf(trace,sizeof(trace),"/proc/self/fd/%d",root);assert(len>0);assert(symlinkat(trace,root,"sys/fs")==0);trace_used=0;trace[0]=0;}}
 assert(close(root)==0);
}
static bool exists(const char *relative){char name[PATH_MAX];int n=snprintf(name,sizeof(name),"%s/%s",fixture,relative);assert(n>0&&(size_t)n<sizeof(name));struct stat st;return lstat(name,&st)==0;}
static void retained(void){
 size_t total=0;char name[PATH_MAX],bytes[REPORT_BOUND+1U];
 for(unsigned i=0;i<3U;i++){int n=snprintf(name,sizeof(name),"%s/var/lib/age30-qualification/evidence/" RUN_ID "/%s",fixture,reports[i]);assert(n>0&&(size_t)n<sizeof(name));int fd=open(name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);if(fd<0)continue;
  struct stat st;assert(fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_nlink==1&&(st.st_mode&0777U)==0600U&&st.st_size>=0&&(uint64_t)st.st_size<=REPORT_BOUND);total+=(size_t)st.st_size;ssize_t got=read(fd,bytes,REPORT_BOUND);assert(got>=0);bytes[(size_t)got]=0;
  assert(!strstr(bytes,"\"admission\":true")&&!strstr(bytes,"\"qualified\":true")&&!strstr(bytes,"\"assumptionsVerified\":true"));assert(close(fd)==0);
 }
 assert(total<=EVIDENCE_BOUND);
}
static void complete(void){
 char path[PATH_MAX],text[REPORT_BOUND+1U];int n=snprintf(path,sizeof(path),"%s/var/lib/age30-qualification/evidence/" RUN_ID "/result.json",fixture);assert(n>0&&(size_t)n<sizeof(path));int fd=open(path,O_RDONLY|O_NOFOLLOW);assert(fd>=0);ssize_t got=read(fd,text,REPORT_BOUND);assert(got>0);text[(size_t)got]=0;assert(strstr(text,"\"status\":\"UNKNOWN\"")&&strstr(text,"\"observationsComplete\":true"));assert(close(fd)==0);
}
int main(void){
 assert(getuid()!=0&&geteuid()!=0);(void)umask(0077);
 assert(eligible(1,true,0,0,0,0));assert(!eligible(2,true,0,0,0,0));assert(!eligible(1,false,0,0,0,0));assert(!eligible(1,true,1,0,0,0));assert(!eligible(1,true,0,1,0,0));assert(!eligible(1,true,0,0,1,0));assert(!eligible(1,true,0,0,0,1));
 prepare(0,0);assert(observe()==2);assert(writes==6U&&mkdirs==2U);complete();retained();unsigned boundaries=event;assert(boundaries>100U&&boundaries<450U);
 const char expected[]="mkdir:" RUN_ID "\nmkdir:" LEAF "\nwrite:cpu.max\nwrite:cpu.max.burst\nwrite:memory.max\nwrite:memory.swap.max\nwrite:memory.oom.group\nwrite:pids.max\n";assert(!strcmp(trace,expected));
 FILE *log=fopen("simulated-trace.txt","wx");assert(log);assert(fputs(trace,log)>=0&&fclose(log)==0);
 // A second invocation cannot adopt the retained leaf/evidence or write controls.
 writes=0;mkdirs=0;event=0;assert(observe()==2&&writes==0U&&mkdirs==0U);retained();
 for(unsigned at=1U;at<=boundaries;at++){prepare(0,at);assert(observe()==2);assert(failed);retained();}
 for(unsigned kind=1U;kind<=32U;kind++){if(kind==30U)continue;
  prepare(kind,0);assert(observe()==2);retained();
  if(kind==19U){assert(writes==6U);complete();}else if(kind==12U||kind==13U||kind==14U||kind==22U)assert(writes==1U);else if(kind>=25U&&kind<=27U)assert(writes==2U);else assert(writes==0U);
 }
 // Abrupt interruption after exclusive start creation preserves all evidence; no retry/adoption.
 prepare(30,0);pid_t interrupted=fork();assert(interrupted>=0);if(interrupted==0){(void)observe();_exit(92);}int interrupted_status;assert(waitpid(interrupted,&interrupted_status,0)==interrupted&&WIFEXITED(interrupted_status)&&WEXITSTATUS(interrupted_status)==91);retained();assert(!exists("sys/fs/cgroup/" PARENT "/" LEAF));scenario=0;assert(observe()==2&&writes==0U&&mkdirs==1U);retained();
 // Exact regular-file read boundary and +1, within a private simulated parent.
 prepare(0,0);char read_path[PATH_MAX],read_bytes[READ_BOUND+2U],output[READ_BOUND+1U];size_t length;int read_len=snprintf(read_path,sizeof(read_path),"%s/sys/fs/cgroup/" PARENT,fixture);assert(read_len>0&&(size_t)read_len<sizeof(read_path));int read_dir=open(read_path,O_RDONLY|O_DIRECTORY);assert(read_dir>=0);memset(read_bytes,'a',READ_BOUND+1U);read_bytes[READ_BOUND]=0;put_at(read_dir,"cgroup.procs",read_bytes);assert(read_value(read_dir,"cgroup.procs",output,&length)&&length==READ_BOUND);read_bytes[READ_BOUND]='a';read_bytes[READ_BOUND+1U]=0;put_at(read_dir,"cgroup.procs",read_bytes);assert(!read_value(read_dir,"cgroup.procs",output,&length));assert(close(read_dir)==0);
 // Inclusive report capacity / +1 are checked without writing a fourth artifact.
 struct record bounded;memset(&bounded,0,sizeof(bounded));char payload[REPORT_BOUND];memset(payload,'a',sizeof(payload));assert(append(&bounded,payload,REPORT_BOUND-128U));assert(!append(&bounded,payload,1));
 assert(report_fits(EVIDENCE_BOUND-REPORT_BOUND,REPORT_BOUND));assert(!report_fits(EVIDENCE_BOUND,1U));assert(!report_fits(0U,REPORT_BOUND+1U));
 struct state limit;memset(&limit,0,sizeof(limit));limit.written=EVIDENCE_BOUND;assert(!report_write(&limit,0,"x",1));assert(!report_write(&limit,0,payload,REPORT_BOUND+1U));
 // Two processes race exclusively on a private ordinary-filesystem fixture, not cgroupfs.
 prepare(0,0);pid_t one=fork();assert(one>=0);if(one==0){assert(observe()==2);_exit(0);}pid_t two=fork();assert(two>=0);if(two==0){assert(observe()==2);_exit(0);}int status;assert(waitpid(one,&status,0)==one&&WIFEXITED(status)&&WEXITSTATUS(status)==0);assert(waitpid(two,&status,0)==two&&WIFEXITED(status)&&WEXITSTATUS(status)==0);complete();retained();
 assert(exists("sys/fs/cgroup/" PARENT "/" LEAF));
 printf("SIMULATED fixtures complete: %u cases, %u IO fault boundaries; UNKNOWN, NOT host/kernel enforcement\n",cases,boundaries);return 0;
}
