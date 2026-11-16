// Standalone future owner observer. No CLI integration, admission, workload or cleanup.
// OBSERVER_TEST replaces IO only at compile time in the separate nonroot fixture.
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
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <time.h>
#ifdef __linux__
#include <sys/syscall.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <linux/magic.h>
#include <linux/falloc.h>
#include <dirent.h>

#define READ_BOUND 4096U
#define REPORT_BOUND 16384U
#define EVIDENCE_BOUND 65536U
#define RUN_ID "age30-8bbc3a9d-r1-cgroup-observe-v1"
#define LEAF "cgroup-observe-v1"
#define PARENT "age30-qualification-age30-8bbc3a9d-r1"
static const char *const controls[6]={"cpu.max","cpu.max.burst","memory.max","memory.swap.max","memory.oom.group","pids.max"};
static const char *const values[6]={"20000 100000\n","0\n","536870912\n","0\n","1\n","8\n"};
static const char *const reports[3]={"start.json","observations.json","result.json"};
static const char *const cg_parts[4]={"sys","fs","cgroup",PARENT};
static const char *const evidence_parts[4]={"var","lib","age30-qualification","evidence"};
static bool eligible(int argc,bool linux_os,uid_t uid,uid_t euid,gid_t gid,gid_t egid){return argc==1&&linux_os&&uid==0&&euid==0&&gid==0&&egid==0;}
#ifndef OBSERVER_TEST
static int io_root(void){return open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);}
static int io_open(int dir,const char *name,int flags,bool crossing){struct open_how h={.flags=(uint64_t)(unsigned)flags,.mode=(flags&O_CREAT)?0600U:0U,.resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS};if(!crossing)h.resolve|=RESOLVE_NO_XDEV;return (int)syscall(SYS_openat2,dir,name,&h,sizeof(h));}
static int io_statx(int fd,struct statx *s){return (int)syscall(SYS_statx,fd,"",AT_EMPTY_PATH|AT_NO_AUTOMOUNT,STATX_BASIC_STATS|STATX_MNT_ID,s);}
static int io_self(unsigned which,char *out,size_t cap){
 static const char *const names[8]={"/proc/self/uid_map","/proc/self/gid_map","/proc/self/ns/ipc","/proc/self/ns/mnt","/proc/self/ns/net","/proc/self/ns/pid","/proc/self/ns/user","/proc/self/ns/uts"};
 if(which>=8U)return -1;
 if(which>=2U){ssize_t n=readlink(names[which],out,cap);return n<0?-1:(int)n;}
 int fd=open(names[which],O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
 struct stat s;struct statfs f;ssize_t n=-1;char extra;
 if(fstat(fd,&s)==0&&S_ISREG(s.st_mode)&&fstatfs(fd,&f)==0&&f.f_type==PROC_SUPER_MAGIC){n=read(fd,out,cap);if(n>=0&&read(fd,&extra,1)!=0)n=-1;}
 if(close(fd))n=-1;return n<0?-1:(int)n;
}
#define IO_ROOT io_root
#define IO_OPEN io_open
#define IO_STATX io_statx
#define IO_STAT fstat
#define IO_FS fstatfs
#define IO_MKDIR mkdirat
#define IO_READ read
#define IO_WRITE write
#define IO_SYNC fsync
#define IO_ALLOC(fd) fallocate((fd),FALLOC_FL_KEEP_SIZE,0,(off_t)REPORT_BOUND)
#define IO_DENTS(fd,b,n) syscall(SYS_getdents64,(fd),(b),(n))
#define IO_SELF io_self
#define IO_UNAME uname
#define IO_CLOCK clock_gettime
#endif
struct identity {dev_t dev;ino_t ino;uint64_t mount;};
struct chain {int fd[5];struct identity id[5];const char *const *part;};
struct record {char b[REPORT_BOUND];size_t used;unsigned count;};
struct state {struct chain cg,ev;int dir,leaf,report[3];struct identity dir_id,leaf_id,report_id[3];struct record records;size_t written;uint64_t start;const char *phase,*error;int error_number;bool complete;};
struct dent {uint64_t ino;int64_t off;unsigned short len;unsigned char type;char name[];};
static bool identity(int fd,struct identity *id,bool directory){
 struct stat s;struct statx x;
 if(IO_STAT(fd,&s)||IO_STATX(fd,&x)||!(x.stx_mask&STATX_MNT_ID)||s.st_uid!=0||s.st_gid!=0||(s.st_mode&07022U))return false;
 if(directory?!S_ISDIR(s.st_mode):(!S_ISREG(s.st_mode)||s.st_nlink!=1))return false;
 id->dev=s.st_dev;id->ino=s.st_ino;id->mount=x.stx_mnt_id;return true;
}
static bool same(int fd,const struct identity *id,bool directory){struct identity now;return identity(fd,&now,directory)&&now.dev==id->dev&&now.ino==id->ino&&now.mount==id->mount;}
static bool rebound(int parent,const char *name,int held,const struct identity *id,bool directory,bool crossing){
 int fd=IO_OPEN(parent,name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|(directory?O_DIRECTORY:0),crossing);if(fd<0)return false;
 bool ok=same(fd,id,directory)&&(held<0||same(held,id,directory));if(close(fd))ok=false;return ok;
}
static bool chain_open(struct chain *c,const char *const *parts){
 c->part=parts;c->fd[0]=IO_ROOT();if(c->fd[0]<0||!identity(c->fd[0],&c->id[0],true))return false;
 for(unsigned i=0;i<4U;i++){c->fd[i+1U]=IO_OPEN(c->fd[i],parts[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,true);if(c->fd[i+1U]<0||!identity(c->fd[i+1U],&c->id[i+1U],true))return false;}
 return true;
}
static bool chain_same(const struct chain *c){
 int root_fd=IO_ROOT();if(root_fd<0)return false;bool ok=same(root_fd,&c->id[0],true);if(close(root_fd))ok=false;
 for(unsigned i=0;ok&&i<4U;i++)ok=rebound(c->fd[i],c->part[i],c->fd[i+1U],&c->id[i+1U],true,true);return ok;
}
static bool directories(int fd,bool with_leaf){
 _Alignas(uint64_t) unsigned char bytes[READ_BOUND],extra[READ_BOUND];if(lseek(fd,0,SEEK_SET)<0)return false;
 long n=IO_DENTS(fd,bytes,sizeof(bytes));if(n<0||(unsigned long)n>sizeof(bytes)||IO_DENTS(fd,extra,sizeof(extra))!=0)return false;
 size_t at=0;unsigned found=0;
 while(at<(size_t)n){
  if((size_t)n-at<offsetof(struct dent,name)+1U)return false;
  struct dent *d=(struct dent *)(void *)(bytes+at);size_t fixed=offsetof(struct dent,name);
  if(d->len<fixed+1U||d->len>(size_t)n-at||!memchr(d->name,0,(size_t)d->len-fixed))return false;
  if(d->type==DT_DIR){if(strcmp(d->name,".")&&strcmp(d->name,"..")){if(!with_leaf||strcmp(d->name,LEAF)||++found>1U)return false;}}
  else if(d->type!=DT_REG)return false;
  at+=(size_t)d->len;
 }
 return !with_leaf||found==1U;
}
static bool append(struct record *r,const char *bytes,size_t n){if(r->used>REPORT_BOUND-128U||n>REPORT_BOUND-128U-r->used)return false;memcpy(r->b+r->used,bytes,n);r->used+=n;return true;}
static bool literal(struct record *r,const char *s){return append(r,s,strlen(s));}
static bool quoted(struct record *r,const char *p,size_t n){
 if(!literal(r,"\""))return false;
 for(size_t i=0;i<n;i++){unsigned char ch=(unsigned char)p[i];char escaped[7];
  if(ch<32U||ch>=127U||ch=='"'||ch=='\\'){int len=snprintf(escaped,sizeof(escaped),"\\u%04x",(unsigned)ch);if(len!=6||!append(r,escaped,6))return false;}
  else if(!append(r,p+i,1))return false;
 }
 return literal(r,"\"");
}
static bool add_record(struct state *s,const char *name,const char *value,size_t n){
 struct record *r=&s->records;size_t old=r->used;
 if((r->count&&!literal(r,","))||!literal(r,"{\"name\":")||!quoted(r,name,strlen(name))||!literal(r,",\"value\":")||!quoted(r,value,n)||!literal(r,"}")){r->used=old;return false;}
 r->count++;return true;
}
static bool read_identified(int dir,const char *name,char out[READ_BOUND+1U],size_t *len,const struct identity *expected){
 int fd=IO_OPEN(dir,name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,false);if(fd<0)return false;
 struct identity id;char extra;bool ok=identity(fd,&id,false)&&(!expected||same(fd,expected,false));
 ssize_t n=ok?IO_READ(fd,out,READ_BOUND+1U):-1;
 ok=n>=0&&(size_t)n<=READ_BOUND&&IO_READ(fd,&extra,1)==0&&same(fd,&id,false);
 if(close(fd))ok=false;if(!ok)return false;*len=(size_t)n;out[*len]=0;return memchr(out,0,*len)==NULL;
}
static bool read_value(int dir,const char *name,char out[READ_BOUND+1U],size_t *len){return read_identified(dir,name,out,len,NULL);}
static bool read_record(struct state *s,int dir,const char *name,const char *label,char out[READ_BOUND+1U],size_t *len){return read_value(dir,name,out,len)&&add_record(s,label,out,*len);}
static bool has_controller(const char *b,const char *word){
 size_t n=strlen(word);const char *p=b;
 while(*p){while(*p==' '||*p=='\n')p++;const char *end=p;while(*end&&*end!=' '&&*end!='\n')end++;if((size_t)(end-p)==n&&!memcmp(p,word,n))return true;p=end;}return false;
}
static bool empty(int dir){
 char b[READ_BOUND+1U];size_t n;if(!read_value(dir,"cgroup.procs",b,&n)||n!=0U||!read_value(dir,"cgroup.events",b,&n))return false;
 // Exact keyed line parsing; missing/duplicate populated or nonzero denies.
 bool seen=false;size_t at=0;
 while(at<n){char *end=memchr(b+at,'\n',n-at);if(!end)return false;size_t width=(size_t)(end-(b+at));
  if(width>=10U&&!memcmp(b+at,"populated ",10)){if(seen||width!=11U||b[at+10U]!='0')return false;seen=true;}at+=(width+1U);}
 return seen;
}
static bool deadline(struct state *s){struct timespec now;if(IO_CLOCK(CLOCK_MONOTONIC,&now)||now.tv_sec<0)return false;uint64_t ms=(uint64_t)now.tv_sec*1000U+(uint64_t)now.tv_nsec/1000000U;return ms>=s->start&&ms-s->start<10000U;}
static bool private_mode(int fd,mode_t mode){struct stat st;return IO_STAT(fd,&st)==0&&(st.st_mode&07777U)==mode;}
static bool stable(struct state *s,bool leaf){
 if(!private_mode(s->dir,0700)||!deadline(s)||!chain_same(&s->cg)||!chain_same(&s->ev)||!rebound(s->ev.fd[4],RUN_ID,s->dir,&s->dir_id,true,false)||!empty(s->cg.fd[4])||!directories(s->cg.fd[4],leaf))return false;
 for(unsigned i=0;i<3U;i++)if(!private_mode(s->report[i],0600)||!rebound(s->dir,reports[i],s->report[i],&s->report_id[i],false,false))return false;
 return !leaf||(rebound(s->cg.fd[4],LEAF,s->leaf,&s->leaf_id,true,false)&&empty(s->leaf)&&directories(s->leaf,false));
}
static bool report_fits(size_t used,size_t n){return n<=REPORT_BOUND&&used<=EVIDENCE_BOUND&&n<=EVIDENCE_BOUND-used;}
static bool report_write(struct state *s,unsigned which,const char *b,size_t n){
 struct stat st;if(which>=3U||!report_fits(s->written,n)||IO_STAT(s->report[which],&st)||st.st_size!=0||
 !private_mode(s->report[which],0600)||!private_mode(s->dir,0700)||
 !rebound(s->dir,reports[which],s->report[which],&s->report_id[which],false,false))return false;
 ssize_t written=IO_WRITE(s->report[which],b,n);if(written>0)s->written+=(size_t)written;
 return written==(ssize_t)n&&IO_SYNC(s->report[which])==0;
}
static bool make_reports(struct state *s){
 if(IO_MKDIR(s->ev.fd[4],RUN_ID,0700))return false;
 s->dir=IO_OPEN(s->ev.fd[4],RUN_ID,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,false);
 if(s->dir<0||!identity(s->dir,&s->dir_id,true)||!private_mode(s->dir,0700))return false;
 for(unsigned i=0;i<3U;i++){
  s->report[i]=IO_OPEN(s->dir,reports[i],O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,false);
  if(s->report[i]<0||!identity(s->report[i],&s->report_id[i],false))return false;
  struct stat st;if(IO_STAT(s->report[i],&st)||(st.st_mode&0777U)!=0600U||IO_ALLOC(s->report[i])||IO_SYNC(s->report[i]))return false;
 }
 return IO_SYNC(s->dir)==0&&IO_SYNC(s->ev.fd[4])==0;
}
static bool summary(struct state *s,unsigned which,bool complete){
 char b[2048];int n=snprintf(b,sizeof(b),"{\"version\":1,\"type\":\"age30.empty-cgroup-observation\",\"runId\":\"" RUN_ID "\",\"status\":\"UNKNOWN\",\"admission\":false,\"qualified\":false,\"assumptionsVerified\":false,\"observationsComplete\":%s,\"phase\":\"%s\",\"error\":\"%s\",\"errorErrno\":%d,\"parent\":{\"dev\":\"%llu\",\"ino\":\"%llu\",\"mount\":\"%llu\"},\"leaf\":{\"dev\":\"%llu\",\"ino\":\"%llu\",\"mount\":\"%llu\"},\"evidence\":{\"dev\":\"%llu\",\"ino\":\"%llu\",\"mount\":\"%llu\"}}\n",complete?"true":"false",s->phase,s->error?s->error:"none",s->error_number,(unsigned long long)s->cg.id[4].dev,(unsigned long long)s->cg.id[4].ino,(unsigned long long)s->cg.id[4].mount,(unsigned long long)s->leaf_id.dev,(unsigned long long)s->leaf_id.ino,(unsigned long long)s->leaf_id.mount,(unsigned long long)s->dir_id.dev,(unsigned long long)s->dir_id.ino,(unsigned long long)s->dir_id.mount);
 return n>0&&(size_t)n<sizeof(b)&&report_write(s,which,b,(size_t)n);
}
static int observe(void){
 struct state s;memset(&s,0,sizeof(s));for(unsigned i=0;i<5U;i++){s.cg.fd[i]=-1;s.ev.fd[i]=-1;}for(unsigned i=0;i<3U;i++)s.report[i]=-1;s.dir=-1;s.leaf=-1;s.phase="prerequisite";s.error="prerequisite";errno=0;
 char b[READ_BOUND+1U],label[96];size_t n;struct timespec now;struct statfs f;
 if(IO_CLOCK(CLOCK_MONOTONIC,&now)||now.tv_sec<0)goto done;s.start=(uint64_t)now.tv_sec*1000U+(uint64_t)now.tv_nsec/1000000U;
 if(!chain_open(&s.cg,cg_parts)||!chain_open(&s.ev,evidence_parts)||IO_FS(s.cg.fd[4],&f)||f.f_type!=CGROUP2_SUPER_MAGIC||!chain_same(&s.cg)||!chain_same(&s.ev)||!directories(s.cg.fd[4],false)||!empty(s.cg.fd[4]))goto done;
 if(!literal(&s.records,"{\"version\":1,\"status\":\"UNKNOWN\",\"admission\":false,\"qualified\":false,\"assumptionsVerified\":false,\"records\":["))goto done;
 const char *const parent_names[5]={"cgroup.type","cgroup.controllers","cgroup.subtree_control","cgroup.events","cgroup.procs"};
 for(unsigned i=0;i<5U;i++){
  int len=snprintf(label,sizeof(label),"parent.%s",parent_names[i]);if(len<0||(size_t)len>=sizeof(label)||!read_record(&s,s.cg.fd[4],parent_names[i],label,b,&n))goto done;
  if((i==0U&&strcmp(b,"domain\n"))||((i==1U||i==2U)&&(!has_controller(b,"cpu")||!has_controller(b,"memory")||!has_controller(b,"pids"))))goto done;
 }
 struct utsname u;if(IO_UNAME(&u)||!add_record(&s,"self.kernel.release",u.release,strnlen(u.release,sizeof(u.release)))||!add_record(&s,"self.kernel.arch",u.machine,strnlen(u.machine,sizeof(u.machine))))goto done;
 const char *const self_names[8]={"self.uid_map","self.gid_map","self.ns.ipc","self.ns.mnt","self.ns.net","self.ns.pid","self.ns.user","self.ns.uts"};
 for(unsigned i=0;i<8U;i++){int len=IO_SELF(i,b,READ_BOUND+1U);if(len<0||(unsigned)len>READ_BOUND||!add_record(&s,self_names[i],b,(size_t)len))goto done;}
 s.phase="evidence";s.error="evidence_io";if(!make_reports(&s))goto done;
 s.phase="start";s.error=NULL;if(!summary(&s,0,false)||IO_SYNC(s.dir)||IO_SYNC(s.ev.fd[4])){s.error="start_io";goto done;}
 s.phase="leaf_create";s.error="identity_or_population";if(!stable(&s,false))goto done;
 if(IO_MKDIR(s.cg.fd[4],LEAF,0700)){s.error="leaf_exclusive_create";goto done;}
 s.leaf=IO_OPEN(s.cg.fd[4],LEAF,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,false);
 if(s.leaf<0||!identity(s.leaf,&s.leaf_id,true)||s.leaf_id.dev!=s.cg.id[4].dev||s.leaf_id.mount!=s.cg.id[4].mount||IO_FS(s.leaf,&f)||f.f_type!=CGROUP2_SUPER_MAGIC)goto done;
 const char *const leaf_names[7]={"cgroup.type","cgroup.events","cgroup.procs","cpu.stat","memory.current","memory.events","pids.current"};
 for(unsigned phase=0;phase<2U;phase++){
  for(unsigned i=0;i<7U;i++){
   s.phase=phase?"terminal_read":"initial_read";s.error="read_or_identity";
   int len=snprintf(label,sizeof(label),"%s.%s",phase?"terminal":"initial",leaf_names[i]);
   if(len<0||(size_t)len>=sizeof(label)||!stable(&s,true)||!read_record(&s,s.leaf,leaf_names[i],label,b,&n)||(i==0U&&strcmp(b,"domain\n")))goto done;
  }
  if(phase==0U)for(unsigned i=0;i<6U;i++){
   s.phase=controls[i];s.error="write_or_readback";if(!stable(&s,true))goto done;
   int fd=IO_OPEN(s.leaf,controls[i],O_WRONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,false);struct identity id;
   if(fd<0)goto done;bool ok=identity(fd,&id,false)&&id.dev==s.leaf_id.dev&&id.mount==s.leaf_id.mount&&rebound(s.leaf,controls[i],fd,&id,false,false)&&IO_WRITE(fd,values[i],strlen(values[i]))==(ssize_t)strlen(values[i])&&same(fd,&id,false);
   if(close(fd))ok=false;if(!ok||!stable(&s,true)||!rebound(s.leaf,controls[i],-1,&id,false,false))goto done;
   int len=snprintf(label,sizeof(label),"readback.%s",controls[i]);if(len<0||(size_t)len>=sizeof(label)||!read_identified(s.leaf,controls[i],b,&n,&id)||!add_record(&s,label,b,n)||strcmp(b,values[i]))goto done;
  }
 }
 s.phase="complete";s.error=NULL;s.complete=stable(&s,true);
 done:
 s.error_number=s.complete?0:errno;
 if(!s.complete&&!s.error)s.error="identity_or_population";
 // Each report is attempted once only; a missing/partial/unsynced result is UNKNOWN.
 if(s.report[1]>=0&&s.report[2]>=0){
  bool observed=literal(&s.records,"]}\n")&&report_write(&s,1,s.records.b,s.records.used);
  if(!observed){s.complete=false;s.error="observations_io";}
  if(IO_SYNC(s.dir)||IO_SYNC(s.ev.fd[4])){s.complete=false;s.error="evidence_dirsync";}
  if(!summary(&s,2,s.complete)){s.complete=false;s.error="result_io";}
 }
 for(unsigned i=0;i<3U;i++)if(s.report[i]>=0)(void)close(s.report[i]);
 if(s.leaf>=0)(void)close(s.leaf);if(s.dir>=0)(void)close(s.dir);
 for(unsigned i=0;i<5U;i++){if(s.cg.fd[i]>=0)(void)close(s.cg.fd[i]);if(s.ev.fd[i]>=0)(void)close(s.ev.fd[i]);}
 return 2;
}
#ifndef OBSERVER_TEST
int main(int argc,char **argv){
 (void)argv;if(!eligible(argc,true,getuid(),geteuid(),getgid(),getegid())){fputs("AGE30 UNKNOWN: observer invocation refused\n",stderr);return 2;}
 if(syscall(SYS_close_range,3U,UINT_MAX,0U)||clearenv()){fputs("AGE30 UNKNOWN: inherited authority refused\n",stderr);return 2;}
 (void)observe();fputs("AGE30 UNKNOWN: observation only; retain all partial state\n",stderr);return 2;
}
#endif
#else
int main(int argc,char **argv){(void)argc;(void)argv;fputs("AGE30 UNKNOWN: Linux required\n",stderr);return 2;}
#endif
