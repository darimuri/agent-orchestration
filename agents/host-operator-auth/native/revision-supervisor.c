/* One fixed private retainer. No command language, fallback launcher or daemon. */
#include "revision-supervisor-protocol.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/random.h>
#include <sys/xattr.h>
#include <linux/sched.h>
#include <linux/magic.h>
#include <fcntl.h>
#include <poll.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static volatile sig_atomic_t rs_cancelled=0;
static void rs_cancel(int signal_number){(void)signal_number;
rs_cancelled=1;
}
static bool rs_id(const char *s){size_t n=strlen(s);
if(n==0U||n>RS_ID_MAX)return false;
for(size_t i=0U;i<n;i++){unsigned char c=(unsigned char)s[i];
if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'||c==':'))return false;
}return true;
}
static bool rs_clock(uint64_t *wall,uint64_t *mono){struct timespec w,m;
if(clock_gettime(CLOCK_REALTIME,&w)!=0||clock_gettime(CLOCK_MONOTONIC,&m)!=0||w.tv_sec<0||m.tv_sec<0)return false;
*wall=(uint64_t)w.tv_sec*1000U+(uint64_t)w.tv_nsec/1000000U;
*mono=(uint64_t)m.tv_sec*1000U+(uint64_t)m.tv_nsec/1000000U;
return *wall<=RS_MAX_EPOCH;
}
static bool rs_same(const struct stat *a,const struct stat *b){return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_uid==b->st_uid&&a->st_mode==b->st_mode;
}
static bool rs_exact_io(int fd,uint8_t *bytes,size_t n,bool writing,uint64_t end){
  size_t at=0U;
unsigned loops=0U;
while(at<n&&loops++<100000U){ssize_t count=writing?write(fd,bytes+at,n-at):read(fd,bytes+at,n-at);
if(count>0){at+=(size_t)count;
continue;
}if(count==0)return false;
if(errno!=EINTR&&errno!=EAGAIN&&errno!=EWOULDBLOCK)return false;
uint64_t wall,mono;
if(!rs_clock(&wall,&mono)||mono>=end||rs_cancelled)return false;
struct pollfd p={.fd=fd,.events=writing?POLLOUT:POLLIN,.revents=0};
if(poll(&p,1U,10)<0&&errno!=EINTR)return false;
}return at==n;
}
static bool rs_send(const char magic[4],uint8_t *payload,size_t n,uint64_t end){uint8_t h[8];
rs_wire w={h,sizeof(h),0U,true};
rs_emit(&w,magic,4U);
rs_put(&w,(uint64_t)n,4U);
return n<=RS_FRAME_MAX&&rs_exact_io(1,h,sizeof(h),true,end)&&rs_exact_io(1,payload,n,true,end);
}
static bool rs_parse(uint8_t *payload,size_t n,rs_request *q){
  memset(q,0,sizeof(*q));
rs_wire w={payload,n,0U,true};
(void)rs_string(&w,q->run,RS_ID_MAX);
rs_bytes(&w,q->request,32U);
rs_bytes(&w,q->intent,32U);
rs_bytes(&w,q->worker_hash,32U);
(void)rs_string(&w,q->clock,RS_ID_MAX);
q->started=rs_get(&w,8U);
q->deadline=rs_get(&w,8U);
q->wait_ms=(uint32_t)rs_get(&w,4U);
q->input_n=(size_t)rs_get(&w,2U);
  if(q->input_n==0U||q->input_n>RS_INPUT_MAX)return false;
rs_bytes(&w,q->input,q->input_n);
(void)rs_string(&w,q->runtime,RS_PATH_MAX);
(void)rs_string(&w,q->worker,RS_PATH_MAX);
for(size_t i=0U;i<2U;i++){q->dev[i]=rs_get(&w,8U);
q->ino[i]=rs_get(&w,8U);
q->size[i]=rs_get(&w,8U);
}
  return w.ok&&w.at==w.n&&rs_id(q->run)&&rs_id(q->clock)&&q->runtime[0]=='/'&&q->worker[0]=='/'&&q->started<=RS_MAX_EPOCH&&q->deadline<=RS_MAX_EPOCH&&q->deadline>q->started&&q->deadline-q->started<=5000U&&q->wait_ms>0U&&q->wait_ms<=60000U;
}
static bool rs_no_caps(int fd){char value[256];
ssize_t n=fgetxattr(fd,"security.capability",value,sizeof(value));
return n<0&&errno==ENODATA;
}
static bool rs_file_identity(int fd,const char *name,uint64_t dev,uint64_t ino,uint64_t size,uint64_t maximum){struct stat a,b;
if(fstat(fd,&a)!=0||lstat(name,&b)!=0||!rs_same(&a,&b)||!S_ISREG(a.st_mode)||a.st_nlink!=1||b.st_nlink!=1||a.st_uid!=(uid_t)RS_UID||(a.st_mode&07022U)!=0U||a.st_size<1)return false;
return rs_no_caps(fd)&&(uint64_t)a.st_dev==dev&&(uint64_t)a.st_ino==ino&&(uint64_t)a.st_size==size&&size<=maximum;
}
static bool rs_read_file(int dir,const char *name,char *out,size_t max){int fd=openat(dir,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
if(fd<0)return false;
ssize_t n=read(fd,out,max);
bool ok=n>0&&(size_t)n<max;
int saved=errno;
if(close(fd)!=0)ok=false;
errno=saved;
if(ok)out[(size_t)n]='\0';
return ok;
}
static bool rs_no_groups(int fd,const char *allowed){int copy=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
if(copy<0)return false;
DIR *d=fdopendir(copy);
if(d==NULL){(void)close(copy);
return false;
}bool ok=true;
struct dirent *e;
errno=0;
while((e=readdir(d))!=NULL){if(strcmp(e->d_name,".")==0||strcmp(e->d_name,"..")==0)continue;
struct stat s;
if(fstatat(fd,e->d_name,&s,AT_SYMLINK_NOFOLLOW)!=0||S_ISLNK(s.st_mode)){ok=false;
break;
}if(S_ISDIR(s.st_mode)&&(allowed==NULL||(strcmp(e->d_name,allowed)!=0&&strcmp(e->d_name,"supervisor")!=0))){ok=false;
break;
}}if(errno!=0)ok=false;
if(closedir(d)!=0)ok=false;
return ok;
}
static bool rs_domain(int fd){char type[64],control[128];
return rs_read_file(fd,"cgroup.type",type,sizeof(type))&&strcmp(type,"domain\n")==0&&rs_read_file(fd,"cgroup.subtree_control",control,sizeof(control))&&(strcmp(control,"\n")==0||control[0]=='\0');
}
static int rs_populated(int events){char bytes[128];
ssize_t n=pread(events,bytes,sizeof(bytes)-1U,0);
if(n<=0||(size_t)n>=sizeof(bytes)-1U)return -1;
bytes[(size_t)n]='\0';
int found=-1;
char *p=bytes;
while(*p!='\0'){char *end=strchr(p,'\n');
if(end==NULL)return -1;
*end='\0';
if(strncmp(p,"populated ",10U)==0){if(found!=-1||strlen(p)!=11U||(p[10]!='0'&&p[10]!='1'))return -1;
found=p[10]-'0';
}p=end+1;
}return found;
}
static bool rs_child_identity(int child,int events,const char *name,const struct stat *root,const struct stat *leaf,const struct stat *event){struct stat a,b,c,d,p;
if(fstat(3,&p)!=0||!rs_same(root,&p)||fstat(child,&a)!=0||fstatat(3,name,&b,AT_SYMLINK_NOFOLLOW)!=0||fstat(events,&c)!=0||fstatat(child,"cgroup.events",&d,AT_SYMLINK_NOFOLLOW)!=0)return false;
return rs_same(leaf,&a)&&rs_same(leaf,&b)&&rs_same(event,&c)&&rs_same(event,&d)&&rs_no_groups(child,NULL)&&rs_no_groups(3,name)&&rs_domain(child);
}
static bool rs_lock(void){struct stat s;
struct flock l={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=0};
int flags=fcntl(6,F_GETFL);
return fstat(6,&s)==0&&S_ISREG(s.st_mode)&&s.st_uid==(uid_t)RS_UID&&s.st_nlink==1&&(s.st_mode&07777U)==0600U&&lseek(6,0,SEEK_CUR)==0&&flags>=0&&(flags&O_ACCMODE)==O_RDWR&&fcntl(6,F_OFD_SETLK,&l)==0;
}
#ifndef RS_TEST
static bool rs_root_domain(int fd){char type[64];return rs_read_file(fd,"cgroup.type",type,sizeof(type))&&strcmp(type,"domain\n")==0;}
#endif
static bool rs_context(void){
#ifdef RS_TEST
  return rs_test_context();
#else
  struct stat s;
struct statfs v;
if(fstat(3,&s)!=0||!S_ISDIR(s.st_mode)||s.st_uid!=(uid_t)RS_UID||fstatfs(3,&v)!=0||v.f_type!=CGROUP2_SUPER_MAGIC||!rs_root_domain(3)||!rs_no_groups(3,"supervisor"))return false;
  char cgroup[4096],root[4096];
int fd=open("/proc/self/cgroup",O_RDONLY|O_CLOEXEC);
if(fd<0)return false;
ssize_t n=read(fd,cgroup,sizeof(cgroup)-1U);
(void)close(fd);
if(n<=0||(size_t)n>=sizeof(cgroup)-1U)return false;
cgroup[(size_t)n]='\0';
if(strncmp(cgroup,"0::/",4U)!=0||strchr(cgroup,'\n')!=cgroup+n-1)return false;
size_t len=(size_t)n;
if(len<12U||strcmp(cgroup+len-12U,"/supervisor\n")!=0)return false;
cgroup[len-12U]='\0';
ssize_t rn=readlink("/proc/self/fd/3",root,sizeof(root)-1U);
if(rn<1||(size_t)rn>=sizeof(root)-1U)return false;
root[(size_t)rn]='\0';
size_t suffix=strlen(cgroup+3);
return strlen(root)>=suffix&&strcmp(root+strlen(root)-suffix,cgroup+3)==0;
#endif
}
static bool rs_kill(int fd){
#ifdef RS_TEST
  return rs_test_kill(fd);
#else
ssize_t n;
do{n=write(fd,"1",1U);
}while(n<0&&errno==EINTR);
return n==1;
#endif
}
static bool rs_reply(const rs_request *q,const rs_terminal *t,uint64_t end){uint8_t bytes[RS_FRAME_MAX];
rs_wire w={bytes,sizeof(bytes),0U,true};
rs_put(&w,t->status,1U);
rs_put(&w,t->reason,2U);
rs_text(&w,q->run);
rs_emit(&w,t->boundary,32U);
rs_emit(&w,q->request,32U);
rs_emit(&w,q->intent,32U);
rs_emit(&w,q->worker_hash,32U);
rs_text(&w,q->clock);
rs_put(&w,q->started,8U);
rs_put(&w,t->exited,8U);
rs_put(&w,t->settled,8U);
rs_put(&w,t->root_dev,8U);
rs_put(&w,t->root_ino,8U);
rs_put(&w,t->child_dev,8U);
rs_put(&w,t->child_ino,8U);
rs_put(&w,t->reaped,1U);
rs_put(&w,t->no_escape,1U);
rs_put(&w,t->sealed,1U);
rs_put(&w,t->populated,1U);
rs_put(&w,(uint32_t)t->exit_code,4U);
rs_put(&w,t->signal,2U);
rs_put(&w,t->cleanup,1U);
rs_put(&w,(uint64_t)t->out_n,2U);
rs_emit(&w,t->out,t->out_n);
rs_put(&w,(uint64_t)t->err_n,2U);
rs_emit(&w,t->err,t->err_n);
return w.ok&&rs_send("T17A",bytes,w.at,end);
}
static bool rs_drain(int *fd,uint8_t *bytes,size_t *n,bool *overflow){if(*fd<0)return true;
for(unsigned i=0U;i<128U;i++){uint8_t buf[512];
ssize_t got=read(*fd,buf,sizeof(buf));
if(got==0){if(close(*fd)!=0)return false;
*fd=-1;
return true;
}if(got<0){if(errno==EINTR)continue;
return errno==EAGAIN||errno==EWOULDBLOCK;
}size_t count=(size_t)got;
if(*n+count>RS_OUTPUT_MAX){*overflow=true;
continue;
}memcpy(bytes+*n,buf,count);
*n+=count;
}return true;
}
static int rs_run(void){
  rs_request q;
rs_terminal t;
memset(&t,0,sizeof(t));
t.exit_code=-1;
uint64_t wall,mono;
if(!rs_clock(&wall,&mono))return 70;
uint64_t setup_end=mono+2000U;
uint8_t header[8],payload[RS_FRAME_MAX];
  if(syscall(SYS_close_range,7U,UINT_MAX,0U)!=0)return 70;
  for(int fd=0;fd<=6;fd++){int flags=fcntl(fd,F_GETFD);
if(flags<0||fcntl(fd,F_SETFD,flags|FD_CLOEXEC)<0)return 70;
}for(int fd=0;fd<=2;fd++){int flags=fcntl(fd,F_GETFL);
if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0)return 70;
}
  if(!rs_exact_io(0,header,sizeof(header),false,setup_end)||memcmp(header,"Q17A",4U)!=0)return 70;
rs_wire hw={header,sizeof(header),4U,true};
size_t n=(size_t)rs_get(&hw,4U);
if(n==0U||n>RS_FRAME_MAX||!rs_exact_io(0,payload,n,false,setup_end)||!rs_parse(payload,n,&q))return 70;
  t.reason=RS_CONTEXT;
t.cleanup=1U;
  if(!rs_clock(&wall,&mono)||wall<q.started||wall>=q.deadline||q.deadline-wall>5000U)return rs_reply(&q,&t,setup_end)?2:70;
  uint64_t origin_wall=wall,origin_mono=mono,end=mono+q.wait_ms;
if(end>mono+(q.deadline-wall))end=mono+(q.deadline-wall);
  if(!rs_lock()){t.reason=RS_LOCK;
return rs_reply(&q,&t,setup_end)?2:70;
}
  if(!rs_context()||!rs_file_identity(4,q.runtime,q.dev[0],q.ino[0],q.size[0],268435456U)||!rs_file_identity(5,q.worker,q.dev[1],q.ino[1],q.size[1],131072U))return rs_reply(&q,&t,setup_end)?2:70;
  struct stat root,leaf,event;
if(fstat(3,&root)!=0)return 70;
t.root_dev=(uint64_t)root.st_dev;
t.root_ino=(uint64_t)root.st_ino;
  char name[RS_ID_MAX+5U];
int count=snprintf(name,sizeof(name),"run_%s",q.run);
if(count<1||(size_t)count>=sizeof(name))return 70;
  if(mkdirat(3,name,0700)!=0){t.reason=RS_COLLISION;
return rs_reply(&q,&t,setup_end)?2:70;
}
  int child=openat(3,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW),events=-1,killer=-1;
t.cleanup=0U;
  if(child<0)return 70;
#ifdef RS_TEST
  if(!rs_test_prepare(child))return 70;
#endif
  events=openat(child,"cgroup.events",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
killer=openat(child,"cgroup.kill",O_WRONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
  if(events<0||killer<0||fstat(child,&leaf)!=0||fstat(events,&event)!=0||!rs_child_identity(child,events,name,&root,&leaf,&event)||rs_populated(events)!=0)return 70;
  t.child_dev=(uint64_t)leaf.st_dev;
t.child_ino=(uint64_t)leaf.st_ino;
if(getrandom(t.boundary,32U,0)!=32)return 70;
  uint8_t ready[256];
rs_wire rw={ready,sizeof(ready),0U,true};
rs_text(&rw,q.run);
rs_emit(&rw,t.boundary,32U);
rs_put(&rw,t.root_dev,8U);
rs_put(&rw,t.root_ino,8U);
  bool safe=true,launched=false,overflow=false,stopping=false,clock_bad=false,identity_bad=false,leader_reaped=false,no_children=false;
int in[2]={-1,-1},out[2]={-1,-1},err[2]={-1,-1},pidfd=-1,status=0;
pid_t leader=-1;
uint64_t stop_end=0U;
size_t fed=0U;
  if(!rs_send("R17A",ready,rw.at,end)){t.reason=RS_IO;
goto cleanup;
}
  uint8_t go;
if(!rs_exact_io(0,&go,1U,false,end)||go!=RS_GO){t.reason=RS_CANCEL;
goto cleanup;
}
  if(!rs_clock(&wall,&mono)||wall<origin_wall||mono<origin_mono||wall>=q.deadline||mono>=end){t.reason=RS_CLOCK;
goto cleanup;
}
  if(!rs_child_identity(child,events,name,&root,&leaf,&event)||!rs_file_identity(4,q.runtime,q.dev[0],q.ino[0],q.size[0],268435456U)||!rs_file_identity(5,q.worker,q.dev[1],q.ino[1],q.size[1],131072U)){t.reason=RS_IDENTITY;
goto cleanup;
}
  if(pipe2(in,O_CLOEXEC|O_NONBLOCK)!=0||pipe2(out,O_CLOEXEC|O_NONBLOCK)!=0||pipe2(err,O_CLOEXEC|O_NONBLOCK)!=0){t.reason=RS_IO;
goto cleanup;
}
  if(prctl(PR_SET_CHILD_SUBREAPER,1L,0L,0L,0L)!=0){t.reason=RS_REAP;
goto cleanup;
}
  struct clone_args args;
memset(&args,0,sizeof(args));
args.flags=CLONE_INTO_CGROUP|CLONE_PIDFD;
args.exit_signal=SIGCHLD;
args.pidfd=(uint64_t)(uintptr_t)&pidfd;
args.cgroup=(uint64_t)(unsigned)child;
#ifdef RS_TEST
  leader=rs_test_clone(&args);
#else
  leader=(pid_t)syscall(SYS_clone3,&args,sizeof(args));
#endif
  if(leader<0){t.reason=RS_CLONE;
goto cleanup;
}
  if(leader==0){
    if(dup2(in[0],0)<0||dup2(out[1],1)<0||dup2(err[1],2)<0)_exit(127);
    for(int fd=0;fd<3;fd++){int flags=fcntl(fd,F_GETFL);
if(flags<0||fcntl(fd,F_SETFL,flags&~O_NONBLOCK)<0)_exit(127);
}
    if(dup3(4,7,O_CLOEXEC)<0)_exit(127);
if(syscall(SYS_close_range,3U,6U,0U)!=0||syscall(SYS_close_range,8U,UINT_MAX,0U)!=0)_exit(127);
    char *const argv[]={q.runtime,q.worker,NULL};
char *const environment[]={"LANG=C.UTF-8","TZ=UTC",NULL};
    (void)syscall(SYS_execveat,7,"",argv,environment,AT_EMPTY_PATH);
_exit(127);
  }
  launched=true;
(void)close(in[0]);
in[0]=-1;
(void)close(out[1]);
out[1]=-1;
(void)close(err[1]);
err[1]=-1;
  for(unsigned loop=0U;loop<100000U;loop++){
    if(!rs_clock(&wall,&mono)||wall<origin_wall||mono<origin_mono){clock_bad=true;
t.reason=RS_CLOCK;
}else{uint64_t dw=wall-origin_wall,dm=mono-origin_mono;
if(dw>dm+100U||dm>dw+100U){clock_bad=true;
t.reason=RS_CLOCK;
}}
    if(!rs_child_identity(child,events,name,&root,&leaf,&event)){identity_bad=true;
t.reason=RS_IDENTITY;
}
    uint8_t extra;
ssize_t got=read(0,&extra,1U);
if(got==0||got>0||rs_cancelled){stopping=true;
t.reason=RS_CANCEL;
}else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){stopping=true;
t.reason=RS_IO;
}
    if(!rs_drain(&out[0],t.out,&t.out_n,&overflow)||!rs_drain(&err[0],t.err,&t.err_n,&overflow)){stopping=true;
t.reason=RS_IO;
}
    if(overflow){stopping=true;
t.reason=RS_OVERFLOW;
}
    if(!stopping&&in[1]>=0){ssize_t wrote=write(in[1],q.input+fed,q.input_n-fed);
if(wrote>0)fed+=(size_t)wrote;
else if(wrote<0&&errno!=EINTR&&errno!=EAGAIN&&errno!=EWOULDBLOCK){stopping=true;
t.reason=RS_IO;
}if(fed==q.input_n){(void)close(in[1]);
in[1]=-1;
}}
    if(!leader_reaped){siginfo_t info;
memset(&info,0,sizeof(info));
if(waitid(P_PIDFD,(id_t)pidfd,&info,WEXITED|WNOHANG|WNOWAIT)!=0){stopping=true;
t.reason=RS_REAP;
}else if(info.si_pid!=0){pid_t reaped=waitpid(leader,&status,WNOHANG);
if(reaped!=leader){stopping=true;
t.reason=RS_REAP;
}else{leader_reaped=true;
t.reaped=1U;
t.exited=wall;
}}}
    if(leader_reaped){int other_status;
pid_t other;
do{other=waitpid(-1,&other_status,WNOHANG);
}while(other>0);
no_children=other<0&&errno==ECHILD;
}
#ifdef RS_TEST
    rs_test_sample(child,leader_reaped&&no_children);
#endif
    int populated=rs_populated(events);
if(populated<0){identity_bad=true;
t.reason=RS_IDENTITY;
}
    if(leader_reaped&&no_children&&populated==0&&out[0]<0&&err[0]<0)break;
    if(clock_bad){(void)rs_kill(killer);
safe=false;
break;
}
    if(identity_bad||wall>=q.deadline||mono>=end)stopping=true;
    if(stopping&&stop_end==0U){if(!rs_kill(killer)){safe=false;
break;
}stop_end=mono+RS_CLEANUP_MS;
}
    if(stop_end!=0U&&mono>=stop_end){safe=false;
break;
}
    struct pollfd polls[4]={{.fd=0,.events=POLLIN,.revents=0},{.fd=out[0],.events=POLLIN,.revents=0},{.fd=err[0],.events=POLLIN,.revents=0},{.fd=leader_reaped?-1:pidfd,.events=POLLIN,.revents=0}};
    if(poll(polls,4U,10)<0&&errno!=EINTR){safe=false;
break;
}
  }
  if(!leader_reaped||!no_children||rs_populated(events)!=0||!rs_child_identity(child,events,name,&root,&leaf,&event)){safe=false;
goto cleanup;
}
  if(!rs_clock(&wall,&mono)||wall<t.exited||clock_bad||identity_bad){safe=false;
goto cleanup;
}
  t.settled=wall;
t.no_escape=1U;
t.sealed=1U;
t.populated=0U;
  if(WIFEXITED(status))t.exit_code=(int32_t)WEXITSTATUS(status);
else if(WIFSIGNALED(status)&&(WTERMSIG(status)==SIGTERM||WTERMSIG(status)==SIGKILL)){t.signal=(uint16_t)WTERMSIG(status);
}else{t.reason=RS_REAP;
goto cleanup;
}
  if(!overflow&&!rs_cancelled&&t.reason!=RS_CANCEL&&t.reason!=RS_IO&&t.reason!=RS_REAP){t.status=1U;
t.reason=RS_OK;
}
cleanup:
  if(launched&&(!leader_reaped||!no_children)){(void)rs_kill(killer);
safe=false;
}
  if(!rs_child_identity(child,events,name,&root,&leaf,&event)||rs_populated(events)!=0)safe=false;
  if(safe){
#ifdef RS_TEST
    rs_test_remove(child);
#endif
    if(unlinkat(3,name,AT_REMOVEDIR)!=0)safe=false;
else{struct stat gone;
if(fstatat(3,name,&gone,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT)safe=false;
else t.cleanup=1U;
}
  }
  for(size_t i=0U;i<2U;i++){if(in[i]>=0)(void)close(in[i]);
if(out[i]>=0)(void)close(out[i]);
if(err[i]>=0)(void)close(err[i]);
}if(pidfd>=0)(void)close(pidfd);
if(events>=0)(void)close(events);
if(killer>=0)(void)close(killer);
(void)close(child);
  if(!safe||t.cleanup!=1U)return 70;
if(!rs_clock(&wall,&mono))return 70;
if(!rs_reply(&q,&t,mono+RS_CLEANUP_MS))return 70;
return t.status==1U?0:2;
}
#ifndef RS_TEST
int main(int argc,char **argv){
  (void)argv;
if(argc!=1||getuid()!=(uid_t)RS_UID||geteuid()!=(uid_t)RS_UID||getgid()!=(gid_t)RS_UID||getegid()!=(gid_t)RS_UID)return 70;
  (void)umask(0077);
int self=open("/proc/self/exe",O_RDONLY|O_CLOEXEC);
if(self<0||!rs_no_caps(self))return 70;
(void)close(self);
  struct sigaction action;
memset(&action,0,sizeof(action));
action.sa_handler=rs_cancel;
if(sigemptyset(&action.sa_mask)!=0||sigaction(SIGTERM,&action,NULL)!=0||sigaction(SIGINT,&action,NULL)!=0)return 70;
  struct sigaction ignore;
memset(&ignore,0,sizeof(ignore));
ignore.sa_handler=SIG_IGN;
if(sigemptyset(&ignore.sa_mask)!=0||sigaction(SIGPIPE,&ignore,NULL)!=0)return 70;
  pid_t parent=getppid();
if(parent<=1||prctl(PR_SET_PDEATHSIG,SIGTERM,0L,0L,0L)!=0||getppid()!=parent)return 70;
  return rs_run();
}
#endif
