// Unprivileged PID1 broker. The fixed validator alone drives the Git stages.
#include "custody.h"
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <stddef.h>

// Deny networking and escape surfaces even with a private network namespace.
// Architecture mismatch (including x32) kills, rather than selecting a fallback.
#define BLOCK(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(n),0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
static bool filter(void){
#if defined(__x86_64__)
 const unsigned architecture=AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
 const unsigned architecture=AUDIT_ARCH_AARCH64;
#else
 return false;
#endif
#if defined(__x86_64__) || defined(__aarch64__)
 struct sock_filter rules[]={
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,architecture,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
 BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,0x40000000U,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
 BLOCK(__NR_socket),BLOCK(__NR_socketpair),BLOCK(__NR_connect),BLOCK(__NR_bind),BLOCK(__NR_listen),BLOCK(__NR_accept),BLOCK(__NR_accept4),
 BLOCK(__NR_sendmsg),BLOCK(__NR_recvmsg),BLOCK(__NR_sendmmsg),BLOCK(__NR_recvmmsg),
 BLOCK(__NR_mount),BLOCK(__NR_umount2),BLOCK(__NR_pivot_root),BLOCK(__NR_chroot),BLOCK(__NR_setns),BLOCK(__NR_unshare),
 BLOCK(__NR_open_by_handle_at),BLOCK(__NR_name_to_handle_at),BLOCK(__NR_ptrace),BLOCK(__NR_process_vm_readv),BLOCK(__NR_process_vm_writev),
 BLOCK(__NR_bpf),BLOCK(__NR_perf_event_open),BLOCK(__NR_keyctl),BLOCK(__NR_add_key),BLOCK(__NR_request_key),
 BLOCK(__NR_io_uring_setup),BLOCK(__NR_io_uring_enter),BLOCK(__NR_io_uring_register),BLOCK(__NR_userfaultfd),
 BLOCK(__NR_execve),BLOCK(__NR_setuid),BLOCK(__NR_setgid),BLOCK(__NR_setreuid),BLOCK(__NR_setregid),BLOCK(__NR_setresuid),BLOCK(__NR_setresgid),BLOCK(__NR_setgroups),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_clone3,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOSYS),
 // clone is needed for Node threads and Git children, never new namespaces.
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_clone,0,3),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
 BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x7e020080U,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
 BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
 struct sock_fprog program={.len=(unsigned short)(sizeof(rules)/sizeof(rules[0])),.filter=rules};
 return prctl(PR_SET_NO_NEW_PRIVS,1L,0L,0L,0L)==0&&syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program)==0;
#endif
}
#undef BLOCK
static void hex(const uint8_t *in,size_t n,char *out){const char *digits="0123456789abcdef";for(size_t i=0;i<n;i++){out[2U*i]=digits[in[i]>>4];out[2U*i+1U]=digits[in[i]&15U];}out[2U*n]='\0';}
static const char *const environment[]={"LANG=C","LC_ALL=C","TZ=UTC","PATH=/usr/bin","HOME=/work/home","TMPDIR=/work/tmp",
 "GIT_CONFIG_NOSYSTEM=1","GIT_CONFIG_SYSTEM=/dev/null","GIT_CONFIG_GLOBAL=/dev/null","GIT_TERMINAL_PROMPT=0",
 "GIT_NO_REPLACE_OBJECTS=1","GIT_NO_LAZY_FETCH=1","GIT_ALLOW_PROTOCOL=","GIT_OPTIONAL_LOCKS=0",NULL};

// argv is compiled, never decoded from any request. Only 20-byte OIDs become hex.
static bool operation(const ogw_frame *f,char oid[41],char pack[128],char *argv[20],uint64_t *offset,uint64_t *length){
 size_t n=0;argv[n++]=(char *)OGW_GIT;argv[n++]="--no-pager";argv[n++]="--git-dir=/work/repo";
 argv[n++]="-c";argv[n++]="core.hooksPath=/empty";argv[n++]="-c";argv[n++]="gc.auto=0";argv[n++]="-c";argv[n++]="maintenance.auto=false";
 *offset=0;*length=0;
 switch(f->op){
 case OGW_INIT:argv[n++]="init";argv[n++]="--bare";argv[n++]="--object-format=sha1";argv[n++]="--template=/empty";argv[n++]="--quiet";argv[n++]="/work/repo";break;
 case OGW_INDEX_PACK:argv[n++]="index-pack";argv[n++]="--stdin";argv[n++]="--strict";argv[n++]="--max-input-size=33554432";*offset=ogw_get(f->payload,8);*length=ogw_get(f->payload+8,8);break;
 case OGW_VERIFY_PACK:argv[n++]="verify-pack";argv[n++]="-v";argv[n++]=pack;break;
 case OGW_FSCK:argv[n++]="fsck";argv[n++]="--strict";argv[n++]="--full";argv[n++]="--no-reflogs";argv[n++]="--no-dangling";break;
 case OGW_OBJECT_READ:hex(f->payload,20,oid);argv[n++]="cat-file";argv[n++]="--batch";break;
 case OGW_TREE:hex(f->payload,20,oid);argv[n++]="cat-file";argv[n++]="tree";argv[n++]=oid;break;
 default:return false;
 }argv[n]=NULL;return true;
}
static bool single_pack(char pack[128]){
 // Opaque pack spelling is generated from index-pack's strict 40-hex result,
 // never enumerated from a caller-selected path or advertisement.
 return strlen(pack)==strlen("/work/repo/objects/pack/pack-")+44U;
}
static bool execute(const ogw_frame *f,ogw_state *state,int channel,char pack[128]){
 char oid[41],*argv[20];uint64_t offset,length;if(!operation(f,oid,pack,argv,&offset,&length))return false;
 struct stat input;if(fstat(8,&input)||!S_ISREG(input.st_mode)||input.st_size<0||offset>(uint64_t)input.st_size||length>(uint64_t)input.st_size-offset)return false;
 if(f->op==OGW_VERIFY_PACK&&!single_pack(pack))return false;
 int in[2],out[2],err[2];if(pipe2(in,O_CLOEXEC)||pipe2(out,O_CLOEXEC)||pipe2(err,O_CLOEXEC))return false;
 pid_t pid=fork();if(pid<0)return false;
 if(pid==0){if(dup2(in[0],0)<0||dup2(out[1],1)<0||dup2(err[1],2)<0||dup3(5,20,O_CLOEXEC)<0)_exit(127);
  if(syscall(SYS_close_range,3U,19U,0U)||syscall(SYS_close_range,21U,UINT_MAX,0U))_exit(127);
  (void)syscall(SYS_execveat,20,"",argv,environment,AT_EMPTY_PATH);_exit(127);
 }
 (void)close(in[0]);(void)close(out[1]);(void)close(err[1]);
 int fds[3]={in[1],out[0],err[0]};for(unsigned i=0;i<3U;i++){int flags=fcntl(fds[i],F_GETFL);if(flags<0||fcntl(fds[i],F_SETFL,flags|O_NONBLOCK))return false;}
 bool ok=true;uint64_t fed=0,output=0;uint8_t pending[65536];size_t have=0,at=0,index_n=0;char index[64]={0};
 if(f->op==OGW_OBJECT_READ){memcpy(pending,oid,40);pending[40]='\n';have=41U;length=41U;}
 while(fds[0]>=0||fds[1]>=0||fds[2]>=0){
  struct pollfd p[3]={{.fd=fds[0],.events=POLLOUT},{.fd=fds[1],.events=POLLIN},{.fd=fds[2],.events=POLLIN}};
  if(poll(p,3U,100)<0){if(errno==EINTR)continue;ok=false;break;}
  if(fds[0]>=0){if(at==have&&fed<length){size_t want=sizeof(pending);if((uint64_t)want>length-fed)want=(size_t)(length-fed);ssize_t r=pread(8,pending,want,(off_t)(offset+fed));if(r<=0){ok=false;break;}have=(size_t)r;at=0;}
   if(at<have&&(p[0].revents&POLLOUT)){ssize_t r=write(fds[0],pending+at,have-at);if(r>0){at+=(size_t)r;fed+=(uint64_t)r;}else if(r<0&&errno!=EINTR&&errno!=EAGAIN){ok=false;break;}}
   if(fed==length){(void)close(fds[0]);fds[0]=-1;}
   else if(p[0].revents&(POLLERR|POLLHUP|POLLNVAL)){ok=false;break;}
  }
  for(unsigned i=1;i<3U;i++)if(fds[i]>=0&&(p[i].revents&(POLLIN|POLLHUP|POLLERR))){
   uint8_t bytes[OGW_FRAME-OGW_HEADER];ssize_t r=read(fds[i],bytes,sizeof(bytes));
   if(r==0){(void)close(fds[i]);fds[i]=-1;continue;}if(r<0){if(errno==EINTR||errno==EAGAIN)continue;ok=false;break;}
   size_t n=(size_t)r;if(!ogw_charge(state,i==1U?n:0U,i==2U?n:0U)){ok=false;break;}
   if(i==1U){output+=(uint64_t)n;if((f->op==OGW_OBJECT_READ||f->op==OGW_TREE)&&output>OGW_OBJECT+256U){ok=false;break;}
    if(f->op==OGW_INDEX_PACK){if(n>sizeof(index)-index_n){ok=false;break;}memcpy(index+index_n,bytes,n);index_n+=n;}
    if(!ogw_send(channel,f->binding,f->seq,OGW_DATA,bytes,n)){ok=false;break;}
   }
   // Diagnostics are counted and suppressed; object names/messages are untrusted.
  }
  if(!ok)break;
 }
 if(!ok)(void)kill(pid,SIGKILL);for(unsigned i=0;i<3U;i++)if(fds[i]>=0)(void)close(fds[i]);int status;pid_t waited;do{waited=waitpid(pid,&status,0);}while(waited<0&&errno==EINTR);
 if(waited!=pid||!WIFEXITED(status)||WEXITSTATUS(status)!=0)return false;
 if(f->op==OGW_INDEX_PACK){if(index_n!=46U||memcmp(index,"pack\t",5)||index[45]!='\n')return false;index[45]='\0';if(!ogw_hex_name(index+5,40U))return false;int n=snprintf(pack,128,"/work/repo/objects/pack/pack-%s.idx",index+5);if(n<1||n>=128)return false;}
 return ok;
}
static int worker(void){
 // Supervisor enters all namespaces, drops UID/caps and installs this fixed
 // descriptor map before exec. It remains the independent timeout authority.
 if(getuid()!=OGW_UID||geteuid()!=OGW_UID||getgid()!=OGW_UID||getegid()!=OGW_UID||getpid()!=1)return 70;
 uint8_t capsule[496];if(pread(4,capsule,sizeof(capsule),0)!=(ssize_t)sizeof(capsule)||memcmp(capsule,"OGC1",4))return 70;
 int channel[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel))return 70;
 if(mkdir("/work/home",0700)||mkdir("/work/tmp",0700))return 70;
 // Both sides inherit the same filter. Broker/validator can only read/write the
 // already connected private socket; SCM_RIGHTS and socket creation are denied.
 if(!filter())return 70;
 pid_t validator=fork();if(validator<0)return 70;
 if(validator==0){
  // Duplicate above the current descriptor map before overwriting fd3/4/5.
  if(dup3(channel[1],21,O_CLOEXEC)<0||dup3(4,22,O_CLOEXEC)<0||dup3(8,23,O_CLOEXEC)<0||dup3(6,24,O_CLOEXEC)<0)_exit(127);
  if(dup2(21,3)<0||dup2(22,4)<0||dup2(23,5)<0)_exit(127);
  if(syscall(SYS_close_range,6U,23U,0U)||syscall(SYS_close_range,25U,UINT_MAX,0U))_exit(127);
  char *const argv[]={(char *)OGW_NODE,"--v8-pool-size=1",(char *)OGW_VALIDATOR,NULL};(void)syscall(SYS_execveat,24,"",argv,environment,AT_EMPTY_PATH);_exit(127);
 }
 (void)close(channel[1]);ogw_state state={0};uint32_t sequence=0;bool complete=false;char pack[128]={0};
 while(++sequence!=0U){uint8_t bytes[OGW_FRAME+1U];ssize_t n=read(channel[0],bytes,sizeof(bytes));ogw_frame frame;
  if(n<=0||!ogw_decode(bytes,(size_t)n,capsule+8,sequence,&frame)||!ogw_step(&state,frame.op))break;
  if(frame.op==OGW_SETTLE){complete=ogw_send(channel[0],frame.binding,sequence,OGW_END,NULL,0);break;}
  if(!execute(&frame,&state,channel[0],pack)||!ogw_send(channel[0],frame.binding,sequence,OGW_END,NULL,0))break;
 }
 (void)close(channel[0]);if(!complete)(void)kill(validator,SIGKILL);
 int status;pid_t waited;do{waited=waitpid(validator,&status,0);}while(waited<0&&errno==EINTR);
 if(waited!=validator||!complete||!WIFEXITED(status)||WEXITSTATUS(status)!=0)return 70;
 // Namespace PID1 must reap everything; a stray daemon prevents success.
 int other;pid_t remainder=waitpid(-1,&other,WNOHANG);if(remainder!=-1||errno!=ECHILD)return 70;
 return 0;
}
#ifndef OGW_TEST
int main(int argc,char **argv){(void)argv;if(argc!=1)return 70;return worker();}
#endif
