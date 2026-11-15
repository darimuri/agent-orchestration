// Dedicated root-launch-only facility. No listener, installation or host discovery.
#include "custody.h"
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include <linux/magic.h>
#include <linux/capability.h>
#include <linux/mount.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>

// Private immutable launcher capsule, not a caller configuration language.
// OGC2 uses unambiguous v2 inventories; old capsules cannot be reinterpreted.
// 0 magic/version;8 bindings192;200 Git/worker/Node/validator/closure hashes160;
// 360 root/cgroup/runtime dev+ino+mount (9*u64);432 CPU/outer-owner proof hashes64.
#define CAPSULE_SIZE 496U
static uint64_t now_ms(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*1000U+(uint64_t)t.tv_nsec/1000000U;}
static bool nonzero(const uint8_t *b,size_t n){uint8_t v=0;for(size_t i=0;i<n;i++)v|=b[i];return v!=0;}
static void hex32(const uint8_t *b,char text[65]){const char *digits="0123456789abcdef";for(unsigned i=0;i<32U;i++){text[2U*i]=digits[b[i]>>4];text[2U*i+1U]=digits[b[i]&15U];}text[64]='\0';}
static bool read_small(int dir,const char *name,char *b,size_t size){int fd=ogw_open_beneath(dir,name,O_RDONLY);if(fd<0)return false;ssize_t n=pread(fd,b,size-1U,0);bool ok=n>0&&(size_t)n<size-1U;if(close(fd))ok=false;if(ok)b[(size_t)n]='\0';return ok;}
static bool control(int dir,const char *name,const char *value){int fd=ogw_open_beneath(dir,name,O_WRONLY);if(fd<0)return false;bool ok=ogw_write_all(fd,value,strlen(value));if(close(fd))ok=false;char b[128];return ok&&read_small(dir,name,b,sizeof(b))&&!strcmp(b,value);}
static int populated(int dir){char b[256];if(!read_small(dir,"cgroup.events",b,sizeof(b)))return -1;char *p=b;int found=-1;while(*p){char *e=strchr(p,'\n');if(!e)return -1;*e='\0';if(!strncmp(p,"populated ",10U)){if(found!=-1||strlen(p)!=11U||(p[10]!='0'&&p[10]!='1'))return -1;found=p[10]-'0';}p=e+1;}return found;}
static bool cpu_usage(int dir,uint64_t *usage){char b[1024];if(!read_small(dir,"cpu.stat",b,sizeof(b)))return false;bool found=false;char *p=b;while(*p){char *e=strchr(p,'\n');if(!e)return false;*e='\0';if(!strncmp(p,"usage_usec ",11U)){if(found)return false;char *end;errno=0;unsigned long long value=strtoull(p+11,&end,10);if(errno||*end||end==p+11)return false;*usage=(uint64_t)value;found=true;}p=e+1;}return found;}
static bool kill_group(int dir){int fd=ogw_open_beneath(dir,"cgroup.kill",O_WRONLY);if(fd<0)return false;bool ok=ogw_write_all(fd,"1",1);if(close(fd))ok=false;return ok;}
static bool identity(int fd,const uint8_t *numbers){struct stat s;uint64_t mount;return !fstat(fd,&s)&&ogw_mount_id(fd,&mount)&&(uint64_t)s.st_dev==ogw_get(numbers,8)&&(uint64_t)s.st_ino==ogw_get(numbers+8,8)&&mount==ogw_get(numbers+16,8);}
static bool capsule(uint8_t bytes[CAPSULE_SIZE]){
 struct stat s;int seals=fcntl(8,F_GET_SEALS);const int required=F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL;
 if(fstat(8,&s)||!S_ISREG(s.st_mode)||s.st_uid!=0||s.st_size!=CAPSULE_SIZE||seals<0||(seals&required)!=required||pread(8,bytes,CAPSULE_SIZE,0)!=CAPSULE_SIZE||memcmp(bytes,"OGC2",4)||ogw_get(bytes+4,4)!=2U)return false;
 for(unsigned i=0;i<6U;i++)if(!nonzero(bytes+8U+32U*i,32))return false;
 for(unsigned i=0;i<5U;i++)if(!nonzero(bytes+200U+32U*i,32))return false;
 if(!nonzero(bytes+432,32)||!nonzero(bytes+464,32)||!identity(5,bytes+360)||!identity(4,bytes+384)||!identity(6,bytes+408))return false;
 // Every executable and validator is a held, root-owned, non-writable artifact.
 const int descriptors[4]={9,10,11,12};for(unsigned i=0;i<4U;i++){uint8_t digest[32];struct stat a;if(fstat(descriptors[i],&a)||a.st_uid!=0||(a.st_mode&07022U)||!ogw_hash_fd(descriptors[i],268435456U,digest)||memcmp(digest,bytes+200U+32U*i,32))return false;}
 return true;
}
static bool named_fd(int dir,const char *name,int fd){int opened=ogw_open_beneath(dir,name,O_RDONLY);struct stat a,b;bool ok=opened>=0&&!fstat(opened,&a)&&!fstat(fd,&b)&&ogw_same(&a,&b);if(opened>=0)(void)close(opened);return ok;}
static bool root_path(void){
 int fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fd<0)return false;
 const char *parts[]={"var","lib","github-app-agent-gateway","offline-import-v1"};bool ok=true;
 for(unsigned i=0;i<4U;i++){int next=openat(fd,parts[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);struct stat s;
  if(next<0||fstat(next,&s)||!S_ISDIR(s.st_mode)||(s.st_mode&0022U)||s.st_uid!=(i==3U?OGW_HOST_UID:0U))ok=false;
  (void)close(fd);fd=next;if(!ok)break;
 }
 struct stat a,b;uint64_t am,bm;if(ok)ok=!fstat(fd,&a)&&!fstat(5,&b)&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&ogw_mount_id(fd,&am)&&ogw_mount_id(5,&bm)&&am==bm;
 if(fd>=0)(void)close(fd);return ok;
}
static int sort_names(const struct dirent **a,const struct dirent **b){return strcmp((*a)->d_name,(*b)->d_name);}
static bool closure(int dir,unsigned depth,unsigned *count,uint64_t *total,ogw_sha256 *hash,uid_t owner){
 if(depth>16U)return false;struct stat anchor;if(fstat(dir,&anchor)||anchor.st_uid!=owner||!S_ISDIR(anchor.st_mode)||(anchor.st_mode&0022U))return false;
 struct dirent **names=NULL;int n=scandirat(dir,".",&names,NULL,sort_names);if(n<0)return false;bool ok=(unsigned)n<=4098U;
 uint64_t children=0;for(int i=0;i<n;i++)if(strcmp(names[i]->d_name,".")&&strcmp(names[i]->d_name,".."))children++;
 uint8_t child_count[8];ogw_put(child_count,children,8);ogw_hash_update(hash,"[",1);ogw_hash_update(hash,child_count,8);
 for(int i=0;i<n;i++){const char *name=names[i]->d_name;if(ok&&strcmp(name,".")&&strcmp(name,"..")){
  if(++*count>4096U)ok=false;int fd=ok?ogw_open_beneath(dir,name,O_RDONLY):-1;struct stat s;
  if(fd<0||fstat(fd,&s)||s.st_uid!=owner||(s.st_mode&07022U))ok=false;
  if(ok){uint8_t len[8];size_t length=strlen(name);ogw_put(len,length,8);ogw_hash_update(hash,len,8);ogw_hash_update(hash,name,length);
   if(S_ISDIR(s.st_mode)){ogw_hash_update(hash,"D",1);ok=closure(fd,depth+1U,count,total,hash,owner);}
   else if(S_ISREG(s.st_mode)&&s.st_size>=0&&(uint64_t)s.st_size<=536870912U-*total){uint8_t digest[32];*total+=(uint64_t)s.st_size;ok=ogw_hash_fd(fd,268435456U,digest);ogw_hash_update(hash,"F",1);ogw_put(len,(uint64_t)s.st_size,8);ogw_hash_update(hash,len,8);if(ok)ogw_hash_update(hash,digest,32);}
   else ok=false;
  }if(fd>=0)(void)close(fd);
 }free(names[i]);}free(names);ogw_hash_update(hash,"]",1);return ok;
}
static bool prerequisites(const uint8_t c[CAPSULE_SIZE]){
 struct ucred peer;socklen_t size=sizeof(peer);int type;socklen_t tn=sizeof(type);
 if(getsockopt(3,SOL_SOCKET,SO_TYPE,&type,&tn)||type!=SOCK_SEQPACKET||getsockopt(3,SOL_SOCKET,SO_PEERCRED,&peer,&size)||peer.uid!=OGW_HOST_UID||!root_path())return false;
 struct stat root,outer;struct statfs fs;struct statvfs capacity,runtime;
 if(fstat(5,&root)||!ogw_directory(5,OGW_HOST_UID,root.st_dev)||fstatfs(5,&fs)||fs.f_type!=EXT4_SUPER_MAGIC||fstatvfs(5,&capacity)||capacity.f_blocks==0U||capacity.f_frsize==0U||capacity.f_blocks>OGW_SCRATCH/capacity.f_frsize||capacity.f_files>OGW_INODES||capacity.f_files==0U||fstatvfs(6,&runtime)||(runtime.f_flag&ST_RDONLY)==0U||fstat(7,&outer)||!S_ISFIFO(outer.st_mode)||outer.st_uid!=0)return false;
 if(fstatfs(4,&fs)||fs.f_type!=CGROUP2_SUPER_MAGIC||populated(4)!=0)return false;
 char domain[32];if(!read_small(4,"cgroup.type",domain,sizeof(domain))||strcmp(domain,"domain\n"))return false;
 if(!named_fd(6,"usr/bin/git",9)||!named_fd(6,"usr/libexec/ogw-worker",10)||!named_fd(6,"usr/bin/node",11)||!named_fd(6,"validator/entry.mjs",12))return false;
 unsigned count=0;uint64_t total=0;uint8_t digest[32];ogw_sha256 h;ogw_hash_init(&h);ogw_hash_update(&h,"offline-git-runtime/v2\n",sizeof("offline-git-runtime/v2\n")-1U);
 if(!closure(6,0,&count,&total,&h,0))return false;ogw_hash_final(&h,digest);if(memcmp(digest,c+328,32))return false;
 uint64_t usage;if(!cpu_usage(4,&usage)||usage!=0U)return false;
 return control(4,"cpu.max","20000 100000\n")&&control(4,"cpu.max.burst","0\n")&&control(4,"memory.max","536870912\n")&&control(4,"memory.swap.max","0\n")&&control(4,"memory.oom.group","1\n")&&control(4,"pids.max","8\n");
}
static bool drop_privileges(void){
 for(unsigned i=0;i<64U;i++)if(prctl(PR_CAPBSET_DROP,(unsigned long)i,0L,0L,0L)&&errno!=EINVAL)return false;
 if(setgroups(0,NULL)||setresgid(OGW_UID,OGW_UID,OGW_UID)||setresuid(OGW_UID,OGW_UID,OGW_UID))return false;
 struct __user_cap_header_struct header={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};struct __user_cap_data_struct caps[2];memset(caps,0,sizeof(caps));
 return syscall(SYS_capset,&header,caps)==0&&prctl(PR_SET_NO_NEW_PRIVS,1L,0L,0L,0L)==0;
}
static bool sandbox(int stage,int work,int sealed){
 // All mount authority is used before dropping privilege, in a private mount NS.
 if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL))return false;
 // Clone the held runtime mount and attach it at an exclusive private staging
 // mountpoint. Reopen AFTER attach; a pre-mount FD can name the covered mount.
 if(mkdirat(stage,"sandbox",0700))return false;
 int tree=(int)syscall(SYS_open_tree,6,"",AT_EMPTY_PATH|OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC);
 if(tree<0||syscall(SYS_move_mount,tree,"",stage,"sandbox",MOVE_MOUNT_F_EMPTY_PATH))return false;
 int root=openat(stage,"sandbox",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(root<0||fchdir(root)||close(root)||close(tree))return false;
 char source[64];int n;
 n=snprintf(source,sizeof(source),"/proc/self/fd/%d",work);if(n<1||(size_t)n>=sizeof(source)||mount(source,"work",NULL,MS_BIND,NULL))return false;
 if(mount(NULL,"work",NULL,MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))return false;
 n=snprintf(source,sizeof(source),"/proc/self/fd/%d",sealed);if(n<1||(size_t)n>=sizeof(source)||mount(source,"input/bundle",NULL,MS_BIND,NULL)||mount(NULL,"input/bundle",NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))return false;
 if(mount(NULL,".",NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||syscall(SYS_pivot_root,".","oldroot")||chdir("/")||umount2("/oldroot",MNT_DETACH))return false;
 return drop_privileges();
}
static bool normalize(int dir,dev_t device,unsigned depth,unsigned *count){
 if(depth>32U)return false;struct dirent **names=NULL;int n=scandirat(dir,".",&names,NULL,sort_names);if(n<0)return false;bool ok=(unsigned)n<=OGW_INODES;
 for(int i=0;i<n;i++){const char *name=names[i]->d_name;if(ok&&strcmp(name,".")&&strcmp(name,"..")){
  if(++*count>OGW_INODES)ok=false;int fd=ok?ogw_open_beneath(dir,name,O_RDONLY):-1;struct stat s;if(fd<0||fstat(fd,&s)||s.st_dev!=device||s.st_uid!=OGW_UID)ok=false;
  if(ok&&S_ISDIR(s.st_mode))ok=normalize(fd,device,depth+1U,count);
  else if(ok&&(!S_ISREG(s.st_mode)||s.st_nlink!=1))ok=false;
  if(ok&&(fchown(fd,OGW_HOST_UID,OGW_HOST_UID)||fchmod(fd,S_ISDIR(s.st_mode)?0700:0600)))ok=false;
  if(fd>=0)(void)close(fd);
 }free(names[i]);}free(names);return ok;
}
static bool evidence(int fd,const uint8_t *c,unsigned phase){uint8_t b[512];memset(b,0,sizeof(b));memcpy(b,c,CAPSULE_SIZE);ogw_put(b+496,phase,8);return pwrite(fd,b,sizeof(b),0)==(ssize_t)sizeof(b)&&fsync(fd)==0;}
static bool next_request(const uint8_t *c,uint32_t sequence,unsigned op,ogw_frame *out){uint8_t b[OGW_CONTROL+1U];ssize_t n=read(3,b,sizeof(b));return n>0&&ogw_decode(b,(size_t)n,c+8,sequence,out)&&out->op==op;}
static int handoff_adopt(const uint8_t *c,int stage,int quarantine,int candidates,int controlfd,int reserve,const uint8_t inventory[32],const char *name,dev_t device){
 ogw_frame request;ogw_sha256 hash;unsigned count;uint64_t bytes;
 if(!evidence(reserve,c,3U)||!ogw_send(3,c+8,1U,OGW_DATA,inventory,32)||!ogw_send(3,c+8,1U,OGW_END,NULL,0))return 70;
 if(!next_request(c,2U,OGW_SETTLE,&request)||!ogw_send(3,c+8,2U,OGW_END,NULL,0)||!next_request(c,3U,OGW_ADOPT,&request)||memcmp(request.payload,inventory,32))return 70;
 char destination[65];hex32(c+40,destination);
 if(!evidence(reserve,c,4U)||!ogw_adopt(quarantine,name,candidates,destination)||!evidence(reserve,c,5U))return 70;
 int adopted=ogw_open_beneath(candidates,destination,O_RDONLY|O_DIRECTORY);if(adopted<0)return 70;
 uint8_t reread[32];ogw_hash_init(&hash);ogw_hash_update(&hash,"offline-git-custody/v2\n",sizeof("offline-git-custody/v2\n")-1U);ogw_hash_update(&hash,c+8,192);count=0;bytes=0;
 struct stat before,after;if(fstat(stage,&before)||fstat(adopted,&after)||!ogw_same(&before,&after)||!ogw_sync_tree(adopted,device,0,&count,&bytes,&hash))return 70;ogw_hash_final(&hash,reread);if(memcmp(inventory,reread,32))return 70;
 // First-invocation success only after verified normal lock release durability.
 if(unlinkat(controlfd,"session.lock",0)||fsync(controlfd)||!ogw_send(3,c+8,3U,OGW_END,NULL,0))return 70;
 return 0;
}
static int controller(const uint8_t *c,uint64_t start){
 struct timeval timeout={.tv_sec=1,.tv_usec=0};if(setsockopt(3,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))||setsockopt(3,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)))return 70;
 struct stat root;if(fstat(5,&root))return 70;
 int controlfd=ogw_open_beneath(5,"control",O_RDONLY|O_DIRECTORY),inbox=ogw_open_beneath(5,"inbox",O_RDONLY|O_DIRECTORY),quarantine=ogw_open_beneath(5,"quarantine",O_RDONLY|O_DIRECTORY),candidates=ogw_open_beneath(5,"candidates",O_RDONLY|O_DIRECTORY);
 int dirs[4]={controlfd,inbox,quarantine,candidates};for(unsigned i=0;i<4U;i++)if(dirs[i]<0||!ogw_directory(dirs[i],OGW_HOST_UID,root.st_dev))return 70;
 // Stale lock and reserved evidence are deliberately retained. No steal/retry.
 int lock=openat(controlfd,"session.lock",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(lock<0||fchown(lock,OGW_HOST_UID,OGW_HOST_UID)||!evidence(lock,c,1U)||fsync(controlfd))return 70;
 int reserve=ogw_open_beneath(controlfd,"evidence.reserve",O_RDWR);struct stat reserved;
 if(reserve<0||!ogw_regular(reserve,OGW_HOST_UID,root.st_dev,1048576U)||fstat(reserve,&reserved)||reserved.st_size!=1048576||(uint64_t)reserved.st_blocks*512U<1048576U||!evidence(reserve,c,1U))return 70;
 ogw_frame request;if(!next_request(c,1U,OGW_OPEN,&request))return 70;
 char handle[65],name[65];hex32(request.payload,handle);hex32(c+8,name);
 int source=ogw_open_beneath(inbox,handle,O_RDONLY);if(source<0||!ogw_regular(source,OGW_HOST_UID,root.st_dev,OGW_BUNDLE))return 70;
 if(mkdirat(quarantine,name,0700))return 70;int stage=ogw_open_beneath(quarantine,name,O_RDONLY|O_DIRECTORY);if(stage<0||fchown(stage,OGW_HOST_UID,OGW_HOST_UID))return 70;
 int seal=openat(stage,"bundle",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(seal<0||fchown(seal,OGW_HOST_UID,OGW_HOST_UID)||!ogw_copy_seal(source,seal,c+72)||close(source)||close(seal)||fsync(stage))return 70;
 seal=ogw_open_beneath(stage,"bundle",O_RDONLY);if(seal<0)return 70;
 if(mkdirat(stage,"work",0700))return 70;int work=ogw_open_beneath(stage,"work",O_RDONLY|O_DIRECTORY);if(work<0||fchown(work,OGW_UID,OGW_UID)||fsync(stage)||fsync(quarantine)||!evidence(reserve,c,2U))return 70;
 if(now_ms()-start>=OGW_WORK_MS||!identity(4,c+384))return 70;
 int pidfd=-1;struct clone_args args;memset(&args,0,sizeof(args));args.flags=CLONE_INTO_CGROUP|CLONE_PIDFD|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWIPC|CLONE_NEWUTS;args.exit_signal=SIGCHLD;args.pidfd=(uint64_t)(uintptr_t)&pidfd;args.cgroup=4;
 pid_t child=(pid_t)syscall(SYS_clone3,&args,sizeof(args));if(child<0)return 70;
 if(child==0){
  int nullfd=open("/dev/null",O_RDWR|O_NOFOLLOW|O_CLOEXEC);
  if(nullfd<0||dup3(nullfd,40,O_CLOEXEC)<0||!sandbox(stage,work,seal))_exit(127);
  // Collision-free remap through high descriptors, then eliminate all host FDs.
  const int originals[6]={8,9,11,12,seal,10};for(unsigned i=0;i<6U;i++)if(dup3(originals[i],30+(int)i,O_CLOEXEC)<0)_exit(127);
  if(dup3(30,4,O_CLOEXEC)<0||dup3(31,5,O_CLOEXEC)<0||dup3(32,6,O_CLOEXEC)<0||dup3(33,7,O_CLOEXEC)<0||dup3(34,8,O_CLOEXEC)<0||dup3(35,20,O_CLOEXEC)<0)_exit(127);
  // Broker needs fd4..8 across exec; all other inherited capabilities disappear.
  for(int fd=4;fd<=8;fd++)if(fcntl(fd,F_SETFD,0))_exit(127);
  if(dup2(40,0)<0||dup2(40,1)<0||dup2(40,2)<0)_exit(127);
  if(close(3)||syscall(SYS_close_range,9U,19U,0U)||syscall(SYS_close_range,21U,UINT_MAX,0U))_exit(127);
  char *const av[]={"/usr/libexec/ogw-worker",NULL};char *const env[]={"LANG=C","LC_ALL=C","TZ=UTC",NULL};(void)syscall(SYS_execveat,20,"",av,env,AT_EMPTY_PATH);_exit(127);
 }
 bool stopping=false,reaped=false,ok=false;uint64_t stop=0,usage=0;int status=0;
 while(now_ms()-start<OGW_OUTER_MS){
  uint64_t now=now_ms();if(!identity(4,c+384)||!cpu_usage(4,&usage)||usage>=OGW_CPU_GUARD||now-start>=OGW_WORK_MS)stopping=true;
  struct pollfd peer={.fd=3,.events=POLLIN|POLLHUP};if(poll(&peer,1,0)<0||(peer.revents&(POLLHUP|POLLERR|POLLNVAL)))stopping=true;
  // No outer requests are legal while the in-session validator owns execution.
  if(peer.revents&POLLIN)stopping=true;
  if(stopping&&stop==0U){(void)control(4,"cgroup.freeze","1\n");if(!kill_group(4))break;stop=now;}
  if(!reaped){siginfo_t info;memset(&info,0,sizeof(info));if(waitid(P_PIDFD,(id_t)pidfd,&info,WEXITED|WNOHANG|WNOWAIT))break;if(info.si_pid){pid_t r=waitpid(child,&status,WNOHANG);if(r!=child)break;reaped=true;}}
  if(reaped){int other;pid_t r;do{r=waitpid(-1,&other,WNOHANG);}while(r>0);if(r<0&&errno==ECHILD&&populated(4)==0){ok=!stopping&&WIFEXITED(status)&&WEXITSTATUS(status)==0;break;}}
  if(stop&&now-stop>=OGW_SETTLE_MS)break;
  (void)poll(NULL,0,10);
 }
 if(!ok||!identity(4,c+384)||!cpu_usage(4,&usage)||usage>OGW_CPU_FINAL||populated(4)!=0){(void)kill_group(4);return 70;}
 // Worker PID namespace has no process holders, no transferred descriptors and
 // no outside writable bind mounts. It can no longer mutate this inventory.
 int sandbox_dir=ogw_open_beneath(stage,"sandbox",O_RDONLY|O_DIRECTORY);
 if(sandbox_dir<0||fchown(sandbox_dir,OGW_HOST_UID,OGW_HOST_UID)||close(sandbox_dir))return 70;
 unsigned count=0;if(!normalize(work,root.st_dev,0,&count)||fchown(work,OGW_HOST_UID,OGW_HOST_UID)||fchmod(work,0700)||close(work))return 70;
 uint8_t inventory[32];ogw_sha256 hash;ogw_hash_init(&hash);ogw_hash_update(&hash,"offline-git-custody/v2\n",sizeof("offline-git-custody/v2\n")-1U);ogw_hash_update(&hash,c+8,192);count=0;uint64_t bytes=0;
 if(!ogw_sync_tree(stage,root.st_dev,0,&count,&bytes,&hash))return 70;ogw_hash_final(&hash,inventory);
 return handoff_adopt(c,stage,quarantine,candidates,controlfd,reserve,inventory,name,root.st_dev);
}

static bool signal_controller(int pidfd,bool reaped){
 // A held pidfd cannot designate a reused numeric PID. No post-reap signal.
 if(reaped)return true;
 return syscall(SYS_pidfd_send_signal,pidfd,SIGKILL,NULL,0U)==0||errno==ESRCH;
}
static int guard_controller(pid_t controller_pid,int controller_pidfd,const uint8_t *c,uint64_t started){
 bool killed=false,reaped=false;uint64_t kill_at=0;int status=0;
 for(;;){uint64_t now=now_ms();struct pollfd owner={.fd=7,.events=POLLIN|POLLHUP};int result=poll(&owner,1,10);
  bool lost=result<0||(owner.revents&(POLLIN|POLLHUP|POLLERR|POLLNVAL))!=0||!identity(4,c+384)||now-started>=OGW_OUTER_MS;
  if(!reaped){pid_t r=waitpid(controller_pid,&status,WNOHANG);if(r<0)lost=true;else if(r==controller_pid){reaped=true;if(!WIFEXITED(status)||WEXITSTATUS(status)!=0)lost=true;}}
  if(lost&&!killed){(void)kill_group(4);(void)signal_controller(controller_pidfd,reaped);killed=true;kill_at=now;}
  if(reaped&&populated(4)==0){int other;pid_t r;do{r=waitpid(-1,&other,WNOHANG);}while(r>0);if(r<0&&errno==ECHILD)return !killed&&WIFEXITED(status)&&WEXITSTATUS(status)==0?0:70;}
  if(killed&&now-kill_at>=OGW_SETTLE_MS)return 70;
 }
}
static int supervise(void){
 uint64_t started=now_ms();uint8_t c[CAPSULE_SIZE];
 if(started==UINT64_MAX||!capsule(c)||!prerequisites(c)||now_ms()-started>=OGW_WORK_MS||prctl(PR_SET_CHILD_SUBREAPER,1L,0L,0L,0L))return 70;
 int pidfd=-1;struct clone_args args;memset(&args,0,sizeof(args));args.flags=CLONE_PIDFD;args.exit_signal=SIGCHLD;args.pidfd=(uint64_t)(uintptr_t)&pidfd;
 pid_t controller_pid=(pid_t)syscall(SYS_clone3,&args,sizeof(args));if(controller_pid<0)return 70;
 if(controller_pid==0){if(prctl(PR_SET_CHILD_SUBREAPER,1L,0L,0L,0L))_exit(70);_exit(controller(c,started));}
 // clone3 acquires the pidfd atomically: unsupported pidfds cannot leave an
 // unmonitored root controller executing while its guardian returns failure.
 int result=guard_controller(controller_pid,pidfd,c,started);(void)close(pidfd);return result;
}
#ifndef OGW_TEST
int main(int argc,char **argv){(void)argv;if(argc!=1||getuid()!=0||geteuid()!=0||getgid()!=0||getegid()!=0)return 70;
 (void)umask(0077);if(syscall(SYS_close_range,13U,UINT_MAX,0U))return 70;
 // No inherited signal handlers/automatic retry. SIGPIPE becomes UNKNOWN.
 struct sigaction a;memset(&a,0,sizeof(a));a.sa_handler=SIG_IGN;if(sigemptyset(&a.sa_mask)||sigaction(SIGPIPE,&a,NULL))return 70;
 return supervise();}
#endif
