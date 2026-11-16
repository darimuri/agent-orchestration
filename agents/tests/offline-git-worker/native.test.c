// Production functions with compile-time-only fault seams; NO root admission bypass.
#define OGW_TEST 1
#define OGW_HOST_UID ((uid_t)getuid())
#include "../../offline-git-worker/native/custody.h"
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
static unsigned fault,fsync_at,fsync_count,crash_kind;
static int mutate_fd=-1;
static pid_t observed_controller;
static unsigned controller_reaps;
static int controller_status;
static pid_t observe_waitpid(pid_t pid,int *status,int options){
 int local_status;int *out=status?status:&local_status;pid_t result=waitpid(pid,out,options);
 if(result>0&&result==observed_controller){controller_reaps++;controller_status=*out;}
 return result;
}
static ssize_t fault_write(int fd,const void *bytes,size_t n){
 if(fault==1U)return write(fd,bytes,n>1U?1U:n);
 if(fault==2U)return 0;
 if(fault==3U){errno=ENOSPC;return -1;}
 if((fault==5U||fault==6U)&&mutate_fd>=0){assert(pwrite(mutate_fd,"z",1,0)==1);mutate_fd=-1;}
 return write(fd,bytes,n);
}
static int fault_fstat(int fd,struct stat *s){int r=fstat(fd,s);if(r==0&&fault==6U){s->st_mtim.tv_sec=0;s->st_mtim.tv_nsec=0;s->st_ctim.tv_sec=0;s->st_ctim.tv_nsec=0;}return r;}
static int fault_fsync(int fd){
 if(fault==4U){errno=EIO;return -1;}
 unsigned at=++fsync_count;
 if(fsync_at&&at==fsync_at){if(crash_kind==1U)_exit(91);if(crash_kind==0U){errno=EIO;return -1;}}
 int r=fsync(fd);if(fsync_at&&at==fsync_at&&crash_kind==2U)_exit(92);return r;
}
#define write fault_write
#define fstat fault_fstat
#define fsync fault_fsync
#define waitpid observe_waitpid
#include "../../offline-git-worker/native/supervisor.c"
#include "../../offline-git-worker/native/custody.c"
#undef write
#undef fstat
#undef fsync
#undef waitpid
static void digest_vector(const char *text,const char *expected){ogw_sha256 h;uint8_t digest[32];char encoded[65];ogw_hash_init(&h);ogw_hash_update(&h,text,strlen(text));ogw_hash_final(&h,digest);hex32(digest,encoded);assert(!strcmp(encoded,expected));}
static void primitives(void){
 char temporary[]="/tmp/ogw-native-XXXXXX";assert(mkdtemp(temporary));int root=open(temporary,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(root>=0);
 assert(mkdirat(root,"a",0700)==0);assert(mkdirat(root,"b",0700)==0);
 int a=ogw_open_beneath(root,"a",O_RDONLY|O_DIRECTORY),b=ogw_open_beneath(root,"b",O_RDONLY|O_DIRECTORY);assert(a>=0&&b>=0);
 const char *name="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
 const char *other="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
 assert(mkdirat(a,name,0700)==0);assert(mkdirat(b,other,0700)==0);
 assert(!ogw_adopt(a,name,b,other));struct stat s;assert(!fstatat(a,name,&s,AT_SYMLINK_NOFOLLOW));
 assert(!unlinkat(b,other,AT_REMOVEDIR));assert(ogw_adopt(a,name,b,other));assert(fstatat(a,name,&s,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT);
 assert(symlinkat("/etc/passwd",root,"link")==0);assert(ogw_open_beneath(root,"link",O_RDONLY)<0);
 assert(mkfifoat(root,"fifo",0600)==0);int fifo=ogw_open_beneath(root,"fifo",O_RDONLY);assert(fifo>=0);assert(!ogw_regular(fifo,getuid(),s.st_dev,100));assert(close(fifo)==0);
 assert(ogw_open_beneath(root,"../",O_RDONLY|O_DIRECTORY)<0);
 int input=openat(root,"input",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600),copy=openat(root,"copy",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);assert(input>=0&&copy>=0);assert(ogw_write_all(input,"abc",3));
 uint8_t digest[32];assert(ogw_hash_fd(input,3,digest));assert(ogw_copy_seal(input,copy,digest));assert(!ogw_copy_seal(input,copy,digest));assert(linkat(root,"input",root,"hard",0)==0);assert(!ogw_hash_fd(input,3,digest));
 assert(unlinkat(root,"hard",0)==0);
 for(fault=1U;fault<=6U;fault++){
  assert(ftruncate(input,0)==0&&pwrite(input,"abc",3,0)==3&&ftruncate(copy,0)==0&&lseek(copy,0,SEEK_SET)==0);assert(ogw_hash_fd(input,3,digest));
  if(fault==5U||fault==6U)mutate_fd=input;
  bool result=ogw_copy_seal(input,copy,digest);assert(result==(fault==1U));
 }
 fault=0;
 assert(close(input)==0&&close(copy)==0);assert(unlinkat(root,"input",0)==0&&unlinkat(root,"copy",0)==0&&unlinkat(root,"fifo",0)==0&&unlinkat(root,"link",0)==0);
 assert(unlinkat(b,other,AT_REMOVEDIR)==0);
 // REAL two-process no-replace race with distinct sources and one destination.
 const char *target="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
 assert(mkdirat(a,name,0700)==0&&mkdirat(a,other,0700)==0);pid_t racers[2];
 for(unsigned i=0;i<2U;i++){racers[i]=fork();assert(racers[i]>=0);if(racers[i]==0)_exit(ogw_adopt(a,i==0U?name:other,b,target)?0:1);}
 unsigned successes=0;for(unsigned i=0;i<2U;i++){int status;assert(waitpid(racers[i],&status,0)==racers[i]&&WIFEXITED(status));if(WEXITSTATUS(status)==0)successes++;else assert(WEXITSTATUS(status)==1);}assert(successes==1U);
 if(fstatat(a,name,&s,AT_SYMLINK_NOFOLLOW)==0)assert(unlinkat(a,name,AT_REMOVEDIR)==0);
 if(fstatat(a,other,&s,AT_SYMLINK_NOFOLLOW)==0)assert(unlinkat(a,other,AT_REMOVEDIR)==0);
 assert(unlinkat(b,target,AT_REMOVEDIR)==0);assert(close(a)==0&&close(b)==0);assert(unlinkat(root,"a",AT_REMOVEDIR)==0&&unlinkat(root,"b",AT_REMOVEDIR)==0);assert(close(root)==0&&rmdir(temporary)==0);
}
static void store(int dir,const char *name,const char *value){int fd=openat(dir,name,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(fd>=0);assert(ogw_write_all(fd,value,strlen(value)));assert(close(fd)==0);}
static void inventory_vectors(void){
 const char *runtime[2]={"de31271d8e0b8878e4babea43c45c1e02550c6d1d0198b4272ce98e6b0dbf033","7ec9869cdec98d828c6b78326ccdef8a74d5ecc604a9a6d5ca4d6fe2125a05e1"};
 const char *custody[2]={"14ad58966759adffd25a589ea3d1510003288a2c057c9d28356bd6233c028e94","1d542292a1562430954671a41413a25b47912f2e32fbe10398d3e531f427cc36"};
 for(unsigned variant=0;variant<2U;variant++){
  char name[]="ogw-inventory-XXXXXX";assert(mkdtemp(name));int root=open(name,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(root>=0&&mkdirat(root,"a",0700)==0);
  int a=ogw_open_beneath(root,"a",O_RDONLY|O_DIRECTORY);assert(a>=0);store(variant==0U?a:root,"b","x");
  for(unsigned kind=0;kind<2U;kind++){ogw_sha256 h;ogw_hash_init(&h);const char *domain=kind==0U?"offline-git-runtime/v2\n":"offline-git-custody/v2\n";ogw_hash_update(&h,domain,strlen(domain));
   uint8_t binding[192];memset(binding,1,sizeof(binding));if(kind==1U)ogw_hash_update(&h,binding,sizeof(binding));
   struct stat st;assert(fstat(root,&st)==0);unsigned count=0;uint64_t bytes=0;
   bool ok=kind==0U?closure(root,0,&count,&bytes,&h,getuid()):ogw_sync_tree(root,st.st_dev,0,&count,&bytes,&h);
   assert(ok);uint8_t hash[32];char text[65];ogw_hash_final(&h,hash);hex32(hash,text);assert(strcmp(text,kind==0U?runtime[variant]:custody[variant])==0);
  }assert(close(a)==0&&close(root)==0);
 }
}
static bool response(int channel,const uint8_t *scope,uint32_t sequence,unsigned op,uint8_t *payload){
 struct pollfd ready={.fd=channel,.events=POLLIN|POLLHUP};if(poll(&ready,1,3000)<=0)return false;
 uint8_t b[OGW_FRAME];ssize_t n=read(channel,b,sizeof(b));ogw_frame f;if(n<=0||!ogw_decode(b,(size_t)n,scope,sequence,&f)||f.op!=op)return false;if(payload&&f.n)memcpy(payload,f.payload,f.n);return true;
}
static void durability_case(unsigned fail_at,unsigned crash){
 char name[]="ogw-durable-XXXXXX";assert(mkdtemp(name));int root=open(name,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(root>=0);
 assert(mkdirat(root,"q",0700)==0&&mkdirat(root,"c",0700)==0&&mkdirat(root,"control",0700)==0);
 int q=ogw_open_beneath(root,"q",O_RDONLY|O_DIRECTORY),dest=ogw_open_beneath(root,"c",O_RDONLY|O_DIRECTORY),controlfd=ogw_open_beneath(root,"control",O_RDONLY|O_DIRECTORY);assert(q>=0&&dest>=0&&controlfd>=0);
 uint8_t config[496];memset(config,1,sizeof(config));char stage_name[65];hex32(config+8,stage_name);assert(mkdirat(q,stage_name,0700)==0);
 int stage=ogw_open_beneath(q,stage_name,O_RDONLY|O_DIRECTORY);assert(stage>=0);store(stage,"payload","x");store(controlfd,"session.lock","retained");store(controlfd,"evidence.reserve","");
 int reserve=ogw_open_beneath(controlfd,"evidence.reserve",O_RDWR);assert(reserve>=0);struct stat st;assert(fstat(stage,&st)==0);
 ogw_sha256 h;ogw_hash_init(&h);ogw_hash_update(&h,"offline-git-custody/v2\n",23);ogw_hash_update(&h,config+8,192);unsigned count=0;uint64_t bytes=0;assert(ogw_sync_tree(stage,st.st_dev,0,&count,&bytes,&h));uint8_t inventory[32];ogw_hash_final(&h,inventory);
 int sockets[2];assert(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,sockets)==0);pid_t child=fork();assert(child>=0);
 if(child==0){assert(close(sockets[0])==0);assert(dup2(sockets[1],3)>=0);if(sockets[1]!=3)(void)close(sockets[1]);fsync_count=0;fsync_at=fail_at;crash_kind=crash;_exit(handoff_adopt(config,stage,q,dest,controlfd,reserve,inventory,stage_name,st.st_dev));}
 assert(close(sockets[1])==0);uint8_t observed[32];bool ack=false;
 if(response(sockets[0],config+8,1,OGW_DATA,observed)&&response(sockets[0],config+8,1,OGW_END,NULL)){
  assert(memcmp(observed,inventory,32)==0);
  if(ogw_send(sockets[0],config+8,2,OGW_SETTLE,NULL,0)&&response(sockets[0],config+8,2,OGW_END,NULL)&&ogw_send(sockets[0],config+8,3,OGW_ADOPT,observed,32))ack=response(sockets[0],config+8,3,OGW_END,NULL);
 }
 int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status));
 if(fail_at==0U){assert(ack&&WEXITSTATUS(status)==0);assert(fstatat(controlfd,"session.lock",&st,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT);}
 else {assert(!ack&&WEXITSTATUS(status)!=0);struct stat evidence_stat;assert(fstat(reserve,&evidence_stat)==0&&evidence_stat.st_size==512);}
 // Both sides of an interrupted rename remain observable; no retry/adoption or
 // lock stealing is invoked by this harness. Existing targets still refuse.
 bool staged=fstatat(q,stage_name,&st,AT_SYMLINK_NOFOLLOW)==0,adopted=fstatat(dest,stage_name,&st,AT_SYMLINK_NOFOLLOW)==0;assert(staged!=adopted);
 if(adopted){assert(!ogw_adopt(q,stage_name,dest,stage_name));assert(fstatat(dest,stage_name,&st,AT_SYMLINK_NOFOLLOW)==0);}
 assert(close(sockets[0])==0&&close(reserve)==0&&close(stage)==0&&close(controlfd)==0&&close(q)==0&&close(dest)==0&&close(root)==0);
}
static void guardian_cases(void){
 // Actual guardian process/pidfd logic. Regular files model cgroup observations
 // ONLY; this is explicitly SYNTHETIC containment, not a kernel cgroup test.
 for(unsigned scenario=0;scenario<3U;scenario++){
  char name[]="ogw-guardian-XXXXXX";assert(mkdtemp(name));int group=open(name,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(group>=0);
  store(group,"cgroup.events","populated 0\n");store(group,"cgroup.kill","");
  int owners[2];assert(pipe2(owners,O_CLOEXEC)==0);uint8_t config[496];memset(config,1,sizeof(config));struct stat st;uint64_t mount;assert(fstat(group,&st)==0&&ogw_mount_id(group,&mount));ogw_put(config+384,(uint64_t)st.st_dev,8);ogw_put(config+392,(uint64_t)st.st_ino,8);ogw_put(config+400,mount,8);
  pid_t controller_pid=fork();assert(controller_pid>=0);if(controller_pid==0){
   // The simulated launcher is the ONLY lifeline writer. O_CLOEXEC alone
   // cannot close a writer in this fork-only, paused non-owner process.
   assert(close(owners[0])==0&&close(owners[1])==0);
   if(scenario==2U){for(;;)pause();}_exit(scenario==0U?0:70);
  }
  int pidfd=(int)syscall(SYS_pidfd_open,controller_pid,0U);assert(pidfd>=0);
  // Duplicate through high FDs to avoid overwriting group or pipe descriptors.
  int g=fcntl(group,F_DUPFD_CLOEXEC,50),o=fcntl(owners[0],F_DUPFD_CLOEXEC,50);assert(g>=0&&o>=0);assert(dup2(g,4)>=0&&dup2(o,7)>=0);
  observed_controller=controller_pid;controller_reaps=0;controller_status=0;
  uint64_t started=now_ms();
  if(scenario==2U){
   assert(close(owners[1])==0);owners[1]=-1;
   // A retained writer must fail promptly, not pass after the 40s timeout.
   assert(signal(SIGALRM,SIG_DFL)!=SIG_ERR);(void)alarm(5);
  }
  int result=guard_controller(controller_pid,pidfd,config,started);
  if(scenario==2U){
   (void)alarm(0);uint64_t elapsed=now_ms()-started;
   assert(elapsed<OGW_SETTLE_MS+1000U&&OGW_SETTLE_MS+1000U<OGW_OUTER_MS);
   assert(controller_reaps==1U&&WIFSIGNALED(controller_status)&&WTERMSIG(controller_status)==SIGKILL);
   char action[8];assert(read_small(group,"cgroup.kill",action,sizeof(action))&&strcmp(action,"1")==0);
   int status;assert(waitpid(controller_pid,&status,WNOHANG)<0&&errno==ECHILD);
   struct pollfd terminal={.fd=pidfd,.events=POLLIN};assert(poll(&terminal,1U,0)==1&&(terminal.revents&POLLIN));
  }
  assert(result==(scenario==0U?0:70));observed_controller=0;
  assert(signal_controller(pidfd,true)); // already reaped => never signals
  assert(syscall(SYS_pidfd_send_signal,pidfd,0,NULL,0U)<0&&errno==ESRCH);
  if(owners[1]>=0)assert(close(owners[1])==0);(void)close(owners[0]);assert(close(pidfd)==0&&close(g)==0&&close(o)==0);(void)close(group);
 }
}
int main(void){
 (void)umask(0077);assert(signal(SIGPIPE,SIG_IGN)!=SIG_ERR);
 // Keep the production entry reachable to the compiler without running root code.
 (void)supervise;
 digest_vector("","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
 digest_vector("abc","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
 primitives();inventory_vectors();durability_case(0,0);for(unsigned at=1;at<=8U;at++)for(unsigned crash=0;crash<3U;crash++)durability_case(at,crash);guardian_cases();
 puts("REAL source copy/inventory/adoption/fsync-crash/process/pidfd paths; SYNTHETIC cgroup observations; NOT host acceptance");return 0;
}
