// Ordinary-user SIMULATED IO only. Never execute setup/observer or touch cgroupfs.
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
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <linux/magic.h>
#include <linux/falloc.h>
static int t_root(void),t_open(int,const char *,int,bool),t_stat(int,struct stat *),t_statx(int,struct statx *),t_fs(int,struct statfs *),t_mkdir(int,const char *,mode_t),t_mode(int,mode_t),t_sync(int),t_alloc(int),t_clock(clockid_t,struct timespec *);
static ssize_t t_read(int,void *,size_t),t_write(int,const void *,size_t);
static long t_dents(int,void *,size_t);
#define SETUP_FIXTURE 1
#define IO_ROOT t_root
#define IO_OPEN t_open
#define IO_STAT t_stat
#define IO_STATX t_statx
#define IO_FS t_fs
#define IO_MKDIR t_mkdir
#define IO_MODE t_mode
#define IO_READ t_read
#define IO_WRITE t_write
#define IO_SYNC t_sync
#define IO_ALLOC t_alloc
#define IO_DENTS t_dents
#define IO_CLOCK t_clock
#include "host-cgroup-setup.c"
#define FD_MAX 1024U
static char fixture[PATH_MAX],names[FD_MAX][512],trace[65536];
static unsigned scenario,event,fail_at,case_count,control_writes,effects_after_error;
static bool failed,cg[FD_MAX],installed,durable,changed;
static size_t trace_size;
static bool tick(void){event++;if(event==fail_at){failed=true;errno=EIO;return false;}return true;}
static void note(const char *type,const char *name){int n=snprintf(trace+trace_size,sizeof(trace)-trace_size,"%s:%s\n",type,name);assert(n>0&&(size_t)n<sizeof(trace)-trace_size);trace_size+=(size_t)n;}
static void register_fd(int fd,int dir,const char *name){if(fd<0)return;assert((unsigned)fd<FD_MAX);char prefix[512]={0};if(dir>=0)strcpy(prefix,names[dir]);int n=snprintf(names[fd],sizeof(names[fd]),"%s%s%s",prefix,dir>=0?"/":"",name);assert(n>=0&&(size_t)n<sizeof(names[fd]));cg[fd]=(dir>=0&&cg[dir])||!strcmp(name,"cgroup");}
static void put(int dir,const char *name,const char *text){int fd=openat(dir,name,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);assert(fd>=0);size_t n=strlen(text);assert(write(fd,text,n)==(ssize_t)n);assert(close(fd)==0);}
static void cg_files(int fd,bool root){put(fd,"cgroup.type","domain\n");put(fd,"cgroup.controllers","cpu memory pids\n");put(fd,"cgroup.subtree_control",root?"cpu memory pids\n":"");put(fd,"cgroup.procs","");put(fd,"cgroup.events","populated 0\nfrozen 0\n");}
static int t_root(void){if(!tick())return -1;int fd=open(fixture,O_RDONLY|O_DIRECTORY|O_CLOEXEC);register_fd(fd,-1,"");return fd;}
static int t_open(int dir,const char *name,int flags,bool crossing){
 if(!tick())return -1;if(scenario==9U){errno=ENOSYS;return -1;}
 if(flags&O_CREAT){note("create",name);if(failed)effects_after_error++;}
 struct open_how h={.flags=(uint64_t)(unsigned)flags,.mode=(flags&O_CREAT)?0600U:0U,.resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS};if(!crossing)h.resolve|=RESOLVE_NO_XDEV;
 int fd=(int)syscall(SYS_openat2,dir,name,&h,sizeof(h));register_fd(fd,dir,name);return fd;
}
static int t_stat(int fd,struct stat *st){if(!tick())return -1;int r=fstat(fd,st);if(!r){st->st_uid=scenario==10U?10001U:0U;st->st_gid=0;if(scenario==11U)st->st_nlink=2;if(scenario==12U)st->st_mode|=0020U;}return r;}
static int t_statx(int fd,struct statx *x){if(!tick())return -1;if(scenario==13U){errno=ENOSYS;return -1;}int r=(int)syscall(SYS_statx,fd,"",AT_EMPTY_PATH|AT_NO_AUTOMOUNT,STATX_BASIC_STATS|STATX_MNT_ID,x);if(!r&&changed)x->stx_mnt_id++;return r;}
static int t_fs(int fd,struct statfs *f){if(!tick())return -1;int r=fstatfs(fd,f);if(!r&&cg[fd])f->f_type=scenario==14U?TMPFS_MAGIC:CGROUP2_SUPER_MAGIC;return r;}
static int t_mkdir(int dir,const char *name,mode_t mode){
 if(!tick())return -1;assert(mode==0700);note("mkdir",name);if(failed)effects_after_error++;
 assert(!strcmp(name,"age30-qualification")||!strcmp(name,"evidence")||!strcmp(name,"bin")||!strcmp(name,"setup-v1")||!strcmp(name,"age30-qualification-age30-8bbc3a9d-r1"));
 if(cg[dir])assert(installed&&durable);
 int r=mkdirat(dir,name,mode);if(!r&&cg[dir]){int fd=openat(dir,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(fd>=0);cg_files(fd,false);
  if(scenario==15U)put(fd,"cgroup.type","threaded\n");if(scenario==16U)put(fd,"cgroup.procs","123\n");if(scenario==17U)assert(mkdirat(fd,"unexpected-child",0700)==0);if(scenario==18U)put(fd,"cgroup.controllers","cpu memory\n");assert(close(fd)==0);
 }return r;
}
static ssize_t t_read(int fd,void *b,size_t n){
 if(!tick())return -1;if(scenario==19U&&strstr(names[fd],"/bin/cgroup-observe-v1"))return read(fd,b,n>1U?n-2U:n);
 ssize_t r=read(fd,b,n);if(r>0&&scenario==20U&&strstr(names[fd],"/bin/cgroup-observe-v1"))((unsigned char *)b)[0]^=1U;return r;
}
static ssize_t t_write(int fd,const void *bytes,size_t n){
 if(!tick())return -1;
 bool terminal=strstr(names[fd],"/result.json")!=NULL;if(failed&&!terminal)effects_after_error++;
 if(cg[fd]){
  assert(installed&&durable);assert(strstr(names[fd],"/age30-qualification-age30-8bbc3a9d-r1/cgroup.subtree_control"));assert(control_writes++==0U);
  const char literal[]="+cpu +memory +pids\n";assert(n==sizeof(literal)-1U&&!memcmp(bytes,literal,n));note("control","+cpu +memory +pids");
  if(scenario==21U){failed=true;return write(fd,bytes,n-1U);}
  assert(ftruncate(fd,0)==0);assert(lseek(fd,0,SEEK_SET)==0);const char *value=scenario==22U?"cpu memory\n":"cpu memory pids\n";assert(write(fd,value,strlen(value))==(ssize_t)strlen(value));
  if(scenario==23U)changed=true;
  if(scenario==24U){char p[PATH_MAX];int len=snprintf(p,sizeof(p),"%s/sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1",fixture);assert(len>0&&(size_t)len<sizeof(p));int dir=open(p,O_RDONLY|O_DIRECTORY);assert(dir>=0);put(dir,"cgroup.procs","456\n");assert(close(dir)==0);}
  return (ssize_t)n;
 }
 if(strstr(names[fd],"/bin/cgroup-observe-v1")){note("copy","embedded-observer");assert(n==sizeof(observer_bytes)&&!memcmp(bytes,observer_bytes,n));}
 if(scenario==25U&&!terminal){failed=true;return write(fd,bytes,n-1U);}
 if(terminal&&scenario==26U)return write(fd,bytes,n-1U);
 return write(fd,bytes,n);
}
static int t_mode(int fd,mode_t mode){if(!tick())return -1;assert(mode==0500&&!cg[fd]&&strstr(names[fd],"/bin/cgroup-observe-v1"));if(failed)effects_after_error++;note("mode","0500");installed=true;return fchmod(fd,mode);}
static int t_sync(int fd){if(!tick())return -1;if(strstr(names[fd],"/inventory.json")){note("sync","inventory");durable=true;}if(scenario==27U&&strstr(names[fd],"/start.json"))_exit(91);return fsync(fd);}
static int t_alloc(int fd){if(!tick())return -1;if(scenario==28U){errno=ENOSPC;return -1;}note("reserve",strrchr(names[fd],'/')+1);return fallocate(fd,FALLOC_FL_KEEP_SIZE,0,REPORT_BOUND);}
static long t_dents(int fd,void *b,size_t n){if(!tick())return -1;return syscall(SYS_getdents64,fd,b,n);}
static int t_clock(clockid_t which,struct timespec *t){(void)which;if(!tick())return -1;t->tv_sec=scenario==29U&&event>2U?11:0;t->tv_nsec=0;return 0;}
static void prepare(unsigned kind,unsigned fault){
 scenario=kind;fail_at=fault;event=0;failed=false;installed=false;durable=false;changed=false;control_writes=0;effects_after_error=0;trace_size=0;trace[0]=0;memset(cg,0,sizeof(cg));memset(names,0,sizeof(names));
 assert(++case_count<10000U);int n=snprintf(fixture,sizeof(fixture),"case-%04u",case_count);assert(n>0&&(size_t)n<sizeof(fixture));assert(mkdir(fixture,0700)==0);int root=open(fixture,O_RDONLY|O_DIRECTORY);assert(root>=0);
 assert(mkdirat(root,"var",0700)==0);int var=openat(root,"var",O_RDONLY|O_DIRECTORY);assert(var>=0);assert(mkdirat(var,"lib",0700)==0);int lib=openat(var,"lib",O_RDONLY|O_DIRECTORY);assert(lib>=0);
 if(kind==1U)assert(mkdirat(lib,"age30-qualification",0700)==0);if(kind==2U)assert(symlinkat("missing",lib,"age30-qualification")==0);if(kind==3U)assert(mkfifoat(lib,"age30-qualification",0600)==0);
 assert(close(lib)==0&&close(var)==0);assert(mkdirat(root,"sys",0700)==0);int sys=openat(root,"sys",O_RDONLY|O_DIRECTORY);assert(sys>=0);assert(mkdirat(sys,"fs",0700)==0);int sysfs=openat(sys,"fs",O_RDONLY|O_DIRECTORY);assert(sysfs>=0);assert(mkdirat(sysfs,"cgroup",0700)==0);int dir=openat(sysfs,"cgroup",O_RDONLY|O_DIRECTORY);assert(dir>=0);cg_files(dir,true);
 if(kind==4U)assert(mkdirat(dir,"age30-qualification-age30-8bbc3a9d-r1",0700)==0);if(kind==5U)put(dir,"cgroup.controllers","cpu memory\n");if(kind==6U)put(dir,"cgroup.subtree_control","cpu memory\n");if(kind==7U)put(dir,"cgroup.type","threaded\n");if(kind==8U)assert(fchmod(dir,0770)==0);
 if(kind==30U){assert(renameat(dir,"cgroup.controllers",dir,"retained-controllers")==0);assert(symlinkat("retained-controllers",dir,"cgroup.controllers")==0);}
 if(kind==31U){assert(renameat(dir,"cgroup.controllers",dir,"retained-controllers")==0);assert(mkfifoat(dir,"cgroup.controllers",0600)==0);}
 if(kind==32U){assert(linkat(dir,"cgroup.controllers",dir,"linked-controllers",0)==0);}
 assert(close(dir)==0&&close(sysfs)==0&&close(sys)==0&&close(root)==0);
}
static bool exists(const char *name){char full[PATH_MAX];int n=snprintf(full,sizeof(full),"%s/%s",fixture,name);assert(n>0&&(size_t)n<sizeof(full));struct stat st;return lstat(full,&st)==0;}
static bool result(char *b,size_t cap){char full[PATH_MAX];int n=snprintf(full,sizeof(full),"%s/var/lib/age30-qualification/setup-v1/result.json",fixture);assert(n>0&&(size_t)n<sizeof(full));int fd=open(full,O_RDONLY|O_NOFOLLOW);if(fd<0)return false;ssize_t got=read(fd,b,cap-1U);assert(got>=0);b[(size_t)got]=0;assert(close(fd)==0);return got>0;}
static void retained(void){
 char full[PATH_MAX],bytes[REPORT_BOUND+1U];size_t total=0;const char *const reports[]={"start.json","inventory.json","result.json"};
 for(unsigned i=0;i<3U;i++){int n=snprintf(full,sizeof(full),"%s/var/lib/age30-qualification/setup-v1/%s",fixture,reports[i]);assert(n>0&&(size_t)n<sizeof(full));int fd=open(full,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);if(fd<0)continue;struct stat st;assert(fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_nlink==1&&(st.st_mode&07777U)==0600U&&st.st_size>=0&&(uint64_t)st.st_size<=REPORT_BOUND);total+=(size_t)st.st_size;ssize_t got=read(fd,bytes,REPORT_BOUND);assert(got>=0);bytes[(size_t)got]=0;assert(!strstr(bytes,"\"admission\":true")&&!strstr(bytes,"\"qualified\":true"));assert(close(fd)==0);}assert(total<=EVIDENCE_BOUND);assert(effects_after_error==0U);
}
int main(void){
 assert(getuid()!=0&&geteuid()!=0);(void)umask(0077);
 assert(eligible(1,true,true,0,0,0,0));assert(!eligible(2,true,true,0,0,0,0));assert(!eligible(1,false,true,0,0,0,0));assert(!eligible(1,true,false,0,0,0,0));assert(!eligible(1,true,true,1,0,0,0));assert(!eligible(1,true,true,0,1,0,0));assert(!eligible(1,true,true,0,0,1,0));assert(!eligible(1,true,true,0,0,0,1));
 prepare(0,0);assert(setup()==2);unsigned boundaries=event;assert(boundaries>100U);assert(control_writes==1U);char b[REPORT_BOUND+1U];assert(result(b,sizeof(b))&&strstr(b,"\"setupComplete\":true"));retained();
 // Literal oracle independent of production path arrays and effect counts.
 const char golden[]="mkdir:age30-qualification\nmkdir:evidence\nmkdir:bin\nmkdir:setup-v1\ncreate:start.json\nreserve:start.json\ncreate:inventory.json\nreserve:inventory.json\ncreate:result.json\nreserve:result.json\ncreate:cgroup-observe-v1\ncopy:embedded-observer\nmode:0500\nsync:inventory\nmkdir:age30-qualification-age30-8bbc3a9d-r1\ncontrol:+cpu +memory +pids\n";
 assert(!strcmp(trace,golden));FILE *log=fopen("simulated-setup-trace.txt","wx");assert(log&&fputs(trace,log)>=0&&fclose(log)==0);
 event=0;control_writes=0;trace_size=0;trace[0]=0;assert(setup()==2&&control_writes==0U&&trace_size==0U);retained();
 for(unsigned at=1;at<=boundaries;at++){prepare(0,at);assert(setup()==2&&failed);retained();// Terminal-write/sync faults may retain a complete-looking but uncommitted result.}
 for(unsigned kind=1;kind<=32U;kind++){if(kind==27U)continue;prepare(kind,0);assert(setup()==2);retained();assert(control_writes<=1U);if(result(b,sizeof(b))&&kind!=26U)assert(strstr(b,"\"setupComplete\":false"));}
 // First syscall error preserved independently of later syscalls/terminal IO.
 struct state error;memset(&error,0,sizeof(error));errno=ESTALE;assert(!fail(&error,"semantic",0));assert(!fail(&error,"later",EIO));assert(error.number==0&&!strcmp(error.error,"semantic"));memset(&error,0,sizeof(error));assert(!fail(&error,"write",ENOSPC)&&!fail(&error,"later",EBADF));assert(error.number==ENOSPC);
 prepare(27U,0);pid_t p=fork();assert(p>=0);if(!p){(void)setup();_exit(92);}int status;assert(waitpid(p,&status,0)==p&&WIFEXITED(status)&&WEXITSTATUS(status)==91);assert(exists("var/lib/age30-qualification/setup-v1/start.json"));assert(!exists("sys/fs/cgroup/age30-qualification-age30-8bbc3a9d-r1"));scenario=0;assert(setup()==2);retained();
 // Boundary/+1 bounded read, no source-selected paths in production.
 prepare(0,0);struct state s;memset(&s,0,sizeof(s));s.root=add(&s,-1,"/",true,true,O_RDONLY,0);s.sys=add(&s,s.root,"sys",true,true,O_RDONLY,0);s.fs=add(&s,s.sys,"fs",true,true,O_RDONLY,0);s.cg=add(&s,s.fs,"cgroup",true,true,O_RDONLY,0);assert(s.cg>=0);char payload[READ_BOUND+2U],out[READ_BOUND+1U];memset(payload,'a',READ_BOUND+1U);payload[READ_BOUND]=0;put(s.nodes[s.cg].fd,"cgroup.procs",payload);size_t length;assert(read_value(&s,s.cg,"cgroup.procs",out,&length)&&length==READ_BOUND);payload[READ_BOUND]='a';payload[READ_BOUND+1U]=0;put(s.nodes[s.cg].fd,"cgroup.procs",payload);assert(!read_value(&s,s.cg,"cgroup.procs",out,&length));for(unsigned i=0;i<s.count;i++)assert(close(s.nodes[i].fd)==0);
 // Two-process no-adoption race, entirely inside ordinary private fixture storage.
 prepare(0,0);pid_t a=fork();assert(a>=0);if(!a){assert(setup()==2);_exit(0);}pid_t c=fork();assert(c>=0);if(!c){assert(setup()==2);_exit(0);}assert(waitpid(a,&status,0)==a&&WIFEXITED(status)&&WEXITSTATUS(status)==0);assert(waitpid(c,&status,0)==c&&WIFEXITED(status)&&WEXITSTATUS(status)==0);assert(result(b,sizeof(b))&&strstr(b,"\"setupComplete\":true"));retained();
 printf("SIMULATED setup fixtures complete: %u cases, %u IO boundaries; UNKNOWN, no host effects\n",case_count,boundaries);return 0;
}
