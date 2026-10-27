/* Compile-time SYNTHETIC cgroup operations; real disposable pipes/children/waits.
 * Not linked into production. These tests are NOT containment/host acceptance. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <linux/sched.h>
#define RS_TEST 1
#define RS_UID ((unsigned)getuid())
static bool rs_test_prepare(int fd);
static bool rs_test_context(void);
static bool rs_test_kill(int fd);
static pid_t rs_test_clone(struct clone_args *args);
static void rs_test_sample(int fd,bool empty);
static void rs_test_remove(int fd);
#include "../../host-operator-auth/native/revision-supervisor.c"
static int test_fault=0,test_pidfd=-1;
static bool test_sampled=false;
static void write_at(int dir,const char *name,const char *text){int fd=openat(dir,name,O_CREAT|O_TRUNC|O_RDWR|O_CLOEXEC,0600);
assert(fd>=0);
size_t n=strlen(text);
assert(write(fd,text,n)==(ssize_t)n);
assert(close(fd)==0);
}
static bool rs_test_context(void){return test_fault!=1;
}
static bool rs_test_prepare(int fd){write_at(fd,"cgroup.type","domain\n");
write_at(fd,"cgroup.subtree_control","\n");
write_at(fd,"cgroup.events","populated 0\nfrozen 0\n");
write_at(fd,"cgroup.kill","");
return true;
}
static pid_t rs_test_clone(struct clone_args *args){assert(args->flags==(CLONE_INTO_CGROUP|CLONE_PIDFD));
assert(args->exit_signal==SIGCHLD);
if(test_fault==2){errno=ENOSYS;
return -1;
}if(test_fault==3){errno=EACCES;
return -1;
}if(test_fault==4){errno=EBUSY;
return -1;
}pid_t p=fork();
if(p>0){int fd=(int)syscall(SYS_pidfd_open,p,0U);
assert(fd>=0);
*(int *)(uintptr_t)args->pidfd=fd;
test_pidfd=fd;
write_at((int)args->cgroup,"cgroup.events","populated 1\nfrozen 0\n");
}return p;
}
static bool rs_test_kill(int fd){(void)fd;
if(test_pidfd<0)return false;
return syscall(SYS_pidfd_send_signal,test_pidfd,SIGKILL,NULL,0U)==0||errno==ESRCH;
}
static void rs_test_sample(int fd,bool empty){if(empty&&test_fault!=5){if(test_sampled&&test_fault>=10)return;if(test_fault>=10)test_sampled=true;if(test_fault==10||test_fault==11){assert(unlinkat(fd,"cgroup.events",0)==0);if(test_fault==10)write_at(fd,"cgroup.events","populated 0\nfrozen 0\n");return;}if(test_fault==12){assert(mkdirat(fd,"foreign",0700)==0);return;}write_at(fd,"cgroup.events","populated 0\nfrozen 0\n");}
}
static void rs_test_remove(int fd){if(test_fault==9)return;const char *names[]={"cgroup.type","cgroup.subtree_control","cgroup.events","cgroup.kill"};
for(size_t i=0U;i<4U;i++)if(unlinkat(fd,names[i],0)!=0)assert(errno==ENOENT);
}
static void parse_tests(void){
  uint8_t bytes[RS_FRAME_MAX];
rs_wire w={bytes,sizeof(bytes),0U,true};
rs_text(&w,"test-run");
uint8_t hash_bytes[32];
memset(hash_bytes,1,sizeof(hash_bytes));
rs_emit(&w,hash_bytes,32U);
rs_emit(&w,hash_bytes,32U);
rs_emit(&w,hash_bytes,32U);
rs_text(&w,"clock");
rs_put(&w,1000U,8U);
rs_put(&w,6000U,8U);
rs_put(&w,100U,4U);
rs_text(&w,"{}");
rs_text(&w,"/runtime");
rs_text(&w,"/worker");
for(unsigned i=0U;i<6U;i++)rs_put(&w,1U,8U);
assert(w.ok);
rs_request q;
assert(rs_parse(bytes,w.at,&q));
assert(strcmp(q.run,"test-run")==0);
  for(size_t n=0U;n<w.at;n++)assert(!rs_parse(bytes,n,&q));
bytes[w.at]=0U;
assert(!rs_parse(bytes,w.at+1U,&q));
bytes[2]='\0';
assert(!rs_parse(bytes,w.at,&q));
  uint8_t tiny[2]={0U,255U};
rs_wire r={tiny,sizeof(tiny),0U,true};
char name[129];
(void)rs_string(&r,name,128U);
assert(!r.ok);
  assert(rs_id("test-run"));
assert(!rs_id("../bad/path"));
assert(!rs_id(""));
}
static void pipe_tests(void){int p[2];
assert(pipe2(p,O_NONBLOCK|O_CLOEXEC)==0);
assert(write(p[1],"bounded",7U)==7);
assert(close(p[1])==0);
uint8_t bytes[RS_OUTPUT_MAX];
size_t n=0U;
bool overflow=false;
assert(rs_drain(&p[0],bytes,&n,&overflow));
assert(n==7U&&!overflow&&p[0]==-1);
 assert(pipe2(p,O_NONBLOCK|O_CLOEXEC)==0);
uint8_t large[RS_OUTPUT_MAX+1U];
memset(large,'x',sizeof(large));
assert(write(p[1],large,sizeof(large))==(ssize_t)sizeof(large));
assert(close(p[1])==0);
n=0U;
assert(rs_drain(&p[0],bytes,&n,&overflow));
assert(overflow);
uint64_t wall,mono;
assert(rs_clock(&wall,&mono));
assert(pipe2(p,O_NONBLOCK|O_CLOEXEC)==0);
uint8_t byte=0U;
assert(!rs_exact_io(p[0],&byte,1U,false,mono));
assert(close(p[0])==0);
assert(close(p[1])==0);
}
static void run_case(const char *self,int fault){
  char root_name[]="/tmp/native-retainer-test-XXXXXX";
assert(mkdtemp(root_name)!=NULL);
int root=open(root_name,O_DIRECTORY|O_RDONLY|O_CLOEXEC);
assert(root>=0);
write_at(root,"worker","");
write_at(root,"lock","");
char worker_name[PATH_MAX];
int count=snprintf(worker_name,sizeof(worker_name),"%s/worker",root_name);
assert(count>0&&(size_t)count<sizeof(worker_name));
int runtime=open(self,O_RDONLY|O_CLOEXEC),worker_fd=open(worker_name,O_RDONLY|O_CLOEXEC),lock_fd=openat(root,"lock",O_RDWR|O_CLOEXEC);
assert(runtime>=0&&worker_fd>=0&&lock_fd>=0);
write_at(root,"worker","fixture");
struct stat a,b;
assert(fstat(runtime,&a)==0&&fstat(worker_fd,&b)==0);
  int in[2],out[2];
assert(pipe(in)==0&&pipe(out)==0);
pid_t helper=fork();
assert(helper>=0);
if(helper==0){int descriptors[7]={in[0],out[1],2,root,runtime,worker_fd,lock_fd},copies[7];
for(size_t i=0U;i<7U;i++){copies[i]=fcntl(descriptors[i],F_DUPFD_CLOEXEC,20);
assert(copies[i]>=0);
}for(int i=0;i<7;i++)assert(dup2(copies[i],i)==i);
test_fault=fault;
_exit(rs_run());
}
  assert(close(in[0])==0&&close(out[1])==0);
uint64_t wall,mono;
assert(rs_clock(&wall,&mono));
uint8_t payload[RS_FRAME_MAX];
rs_wire w={payload,sizeof(payload),0U,true};
rs_text(&w,"fixture-run");
uint8_t hashes[32];
memset(hashes,1,sizeof(hashes));
for(unsigned i=0U;i<3U;i++)rs_emit(&w,hashes,32U);
rs_text(&w,"fixture-clock");
rs_put(&w,wall,8U);
rs_put(&w,wall+1000U,8U);
rs_put(&w,1000U,4U);
rs_text(&w,fault==6?"descendant":"input");
rs_text(&w,self);
rs_text(&w,worker_name);
rs_put(&w,(uint64_t)a.st_dev,8U);
rs_put(&w,(uint64_t)a.st_ino,8U);
rs_put(&w,(uint64_t)a.st_size,8U);
rs_put(&w,(uint64_t)b.st_dev,8U);
rs_put(&w,(uint64_t)b.st_ino,8U);
rs_put(&w,(uint64_t)b.st_size,8U);
assert(w.ok);
uint8_t frame_header[8];
rs_wire h={frame_header,sizeof(frame_header),0U,true};
rs_emit(&h,"Q17A",4U);
rs_put(&h,(uint64_t)w.at,4U);
assert(rs_exact_io(in[1],frame_header,8U,true,mono+2000U));
assert(rs_exact_io(in[1],payload,w.at,true,mono+2000U));
  assert(rs_exact_io(out[0],frame_header,8U,false,mono+4000U));
rs_wire rh={frame_header,8U,4U,true};
size_t n=(size_t)rs_get(&rh,4U);
assert(n<=RS_FRAME_MAX);
assert(rs_exact_io(out[0],payload,n,false,mono+4000U));
if(memcmp(frame_header,"R17A",4U)==0){uint8_t go=RS_GO;
assert(rs_exact_io(in[1],&go,1U,true,mono+2000U));
if(fault==5||fault==9||fault==10||fault==11||fault==12){assert(!rs_exact_io(out[0],frame_header,8U,false,mono+5000U));int failed;assert(waitpid(helper,&failed,0)==helper&&WIFEXITED(failed)&&WEXITSTATUS(failed)==70);int leaf=openat(root,"run_fixture-run",O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(leaf>=0);test_fault=0;if(fault==12)assert(unlinkat(leaf,"foreign",AT_REMOVEDIR)==0);rs_test_remove(leaf);assert(close(leaf)==0&&unlinkat(root,"run_fixture-run",AT_REMOVEDIR)==0);goto finished;}
assert(rs_exact_io(out[0],frame_header,8U,false,mono+4000U));
rh=(rs_wire){frame_header,8U,4U,true};
n=(size_t)rs_get(&rh,4U);
assert(n<=RS_FRAME_MAX);
assert(rs_exact_io(out[0],payload,n,false,mono+4000U));
}
  assert(memcmp(frame_header,"T17A",4U)==0);
assert(payload[0]==((fault==0||fault==6)?1U:0U));
int status;
assert(waitpid(helper,&status,0)==helper);
assert(WIFEXITED(status));
assert(WEXITSTATUS(status)==((fault==0||fault==6)?0:2));
finished:
assert(close(in[1])==0&&close(out[0])==0);
assert(unlinkat(root,"worker",0)==0&&unlinkat(root,"lock",0)==0);
assert(close(runtime)==0&&close(worker_fd)==0&&close(lock_fd)==0&&close(root)==0);
assert(rmdir(root_name)==0);
}
int main(int argc,char **argv){
  if(argc==2){char bytes[32];bool descendant=false;ssize_t got;for(int fd=3;fd<=7;fd++)assert(fcntl(fd,F_GETFD)<0&&errno==EBADF);
while((got=read(0,bytes,sizeof(bytes)-1U))>0){bytes[(size_t)got]=0;if(strstr(bytes,"descendant")!=NULL)descendant=true;}if(descendant){pid_t p=fork();assert(p>=0);if(p==0){assert(usleep(50000U)==0);_exit(0);}}assert(write(1,"fixture",7U)==7);
return 0;
}
  assert(argc==1);
rs_cancel(0);assert(rs_cancelled==1);rs_cancelled=0;
char self[PATH_MAX];
assert(realpath(argv[0],self)!=NULL);
parse_tests();
pipe_tests();
for(int fault=0;fault<=4;fault++)run_case(self,fault);
run_case(self,6);
for(int fault=9;fault<=12;fault++)run_case(self,fault);
run_case(self,5);
puts("native synthetic parser/pipe/clone-denial/retainer fixtures passed; NOT host acceptance");
return 0;
}
