// SYNTHETIC wire/state/dispatch tests; never launches a generic command.
#define OGW_TEST 1
#define OGW_WORK_ROOT "."
#define OGW_EMPTY_ROOT "./empty"
#include "../../offline-git-worker/native/worker.c"
#include "../../offline-git-worker/native/custody.c"
#include <assert.h>
static size_t receive_end(int channel,const uint8_t scope[192],uint32_t sequence,uint8_t *output,size_t capacity){
 size_t total=0;for(;;){struct pollfd p={.fd=channel,.events=POLLIN|POLLHUP};assert(poll(&p,1U,3000)>0);uint8_t bytes[OGW_FRAME];ssize_t n=read(channel,bytes,sizeof(bytes));ogw_frame f;assert(n>0&&ogw_decode(bytes,(size_t)n,scope,sequence,&f));if(f.op==OGW_END)return total;assert(f.op==OGW_DATA&&f.n<=capacity-total);memcpy(output+total,f.payload,f.n);total+=f.n;}
}
static void oid_bytes(const char *hex_oid,uint8_t out[20]){for(unsigned i=0;i<20U;i++){unsigned byte;assert(sscanf(hex_oid+2U*i,"%2x",&byte)==1);out[i]=(uint8_t)byte;}}
static void process_case(unsigned scenario,const uint8_t blob[20],const uint8_t commit[20],const uint8_t tree[20],uint64_t offset,uint64_t length){
 char directory[32];int formatted=snprintf(directory,sizeof(directory),"session-%u",scenario);assert(formatted>0&&(size_t)formatted<sizeof(directory));assert(mkdir(directory,0700)==0);
 int work=open(directory,O_RDONLY|O_DIRECTORY|O_CLOEXEC),git=open(OGW_GIT,O_RDONLY|O_CLOEXEC),bundle=open("bundle",O_RDONLY|O_CLOEXEC);assert(work>=0&&git>=0&&bundle>=0);assert(mkdirat(work,"empty",0700)==0);
 int pair[2];assert(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair)==0);uint8_t scope[192];memset(scope,1,sizeof(scope));pid_t broker=fork();assert(broker>=0);
 if(broker==0){(void)close(pair[0]);assert(fchdir(work)==0);assert(dup3(git,60,O_CLOEXEC)>=0&&dup3(bundle,61,O_CLOEXEC)>=0&&dup3(pair[1],62,O_CLOEXEC)>=0);assert(dup2(60,5)>=0&&dup2(61,8)>=0);_exit(dispatch_session(62,scope)?0:70);}
 int pidfd=(int)syscall(SYS_pidfd_open,broker,0U);assert(pidfd>=0);assert(close(pair[1])==0);uint8_t output[8192];
 assert(ogw_send(pair[0],scope,1,OGW_INIT,NULL,0));(void)receive_end(pair[0],scope,1,output,sizeof(output));
 if(scenario==1U){assert(ogw_send(pair[0],scope,2,OGW_INIT,NULL,0));}
 else if(scenario==2U){assert(close(pair[0])==0);pair[0]=-1;}
 else if(scenario==3U){assert(syscall(SYS_pidfd_send_signal,pidfd,SIGKILL,NULL,0U)==0);}
 else if(scenario==4U){uint8_t other[192];memcpy(other,scope,sizeof(other));other[0]=2;assert(ogw_send(pair[0],other,2,OGW_INDEX_PACK,(uint8_t[16]){0},16)==false);assert(ogw_send(pair[0],other,2,OGW_FSCK,NULL,0));}
 else {
  uint8_t range[16];ogw_put(range,offset,8);ogw_put(range+8,length,8);assert(ogw_send(pair[0],scope,2,OGW_INDEX_PACK,range,16));assert(receive_end(pair[0],scope,2,output,sizeof(output))==46U);
  assert(ogw_send(pair[0],scope,3,OGW_VERIFY_PACK,NULL,0));assert(receive_end(pair[0],scope,3,output,sizeof(output))>0U);
  assert(ogw_send(pair[0],scope,4,OGW_FSCK,NULL,0));(void)receive_end(pair[0],scope,4,output,sizeof(output));
  assert(ogw_send(pair[0],scope,5,OGW_OBJECT_READ,blob,20));size_t n=receive_end(pair[0],scope,5,output,sizeof(output));assert(n>3U&&memmem(output,n," blob 1\nx\n",10)!=NULL);
  assert(ogw_send(pair[0],scope,6,OGW_OBJECT_READ,commit,20));n=receive_end(pair[0],scope,6,output,sizeof(output));assert(memmem(output,n," commit ",8)!=NULL);
  assert(ogw_send(pair[0],scope,7,OGW_TREE,tree,20));n=receive_end(pair[0],scope,7,output,sizeof(output));assert(n==29U&&memmem(output,n,"100644 b\0",9)!=NULL);
  assert(ogw_send(pair[0],scope,8,OGW_SETTLE,NULL,0));(void)receive_end(pair[0],scope,8,output,sizeof(output));
 }
 if(pair[0]>=0){struct pollfd p={.fd=pair[0],.events=POLLIN|POLLHUP};assert(poll(&p,1U,3000)>0);uint8_t b;assert(read(pair[0],&b,1)==0);assert(close(pair[0])==0);}
 int status;assert(waitpid(broker,&status,0)==broker);if(scenario==0U)assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);else if(scenario==3U)assert(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);else assert(WIFEXITED(status)&&WEXITSTATUS(status)==70);
 assert(close(pidfd)==0&&close(work)==0&&close(git)==0&&close(bundle)==0);
}
static void process_sessions(void){
 FILE *metadata=fopen("bundle.metadata","r");assert(metadata);char blob[41],commit[41],tree[41];unsigned long long offset,length;assert(fscanf(metadata,"%40s %40s %40s %llu %llu",blob,commit,tree,&offset,&length)==5);assert(fclose(metadata)==0);uint8_t b[20],c[20],t[20];oid_bytes(blob,b);oid_bytes(commit,c);oid_bytes(tree,t);
 for(unsigned scenario=0;scenario<5U;scenario++)process_case(scenario,b,c,t,(uint64_t)offset,(uint64_t)length);
}
int main(void){
 (void)umask(0077);assert(signal(SIGPIPE,SIG_IGN)!=SIG_ERR);
 (void)worker;ogw_state state={0};assert(ogw_step(&state,OGW_INIT));assert(ogw_step(&state,OGW_INDEX_PACK));assert(ogw_step(&state,OGW_VERIFY_PACK));assert(ogw_step(&state,OGW_FSCK));
 for(unsigned i=0;i<OGW_READS;i++)assert(ogw_step(&state,OGW_OBJECT_READ));assert(!ogw_step(&state,OGW_OBJECT_READ));assert(!ogw_step(&state,OGW_SETTLE));
 state=(ogw_state){0};assert(ogw_charge(&state,OGW_MACHINE,OGW_DIAGNOSTICS));assert(!ogw_charge(&state,1,0));
 state=(ogw_state){0};assert(!ogw_step(&state,OGW_FSCK));
 ogw_frame frame;memset(&frame,0,sizeof(frame));frame.op=OGW_TREE;memset(frame.payload,0xab,20);frame.n=20;
 char oid[41],pack[128]={0},*argv[20];uint64_t offset,length;assert(operation(&frame,oid,pack,argv,&offset,&length));assert(!strcmp(oid,"abababababababababababababababababababab"));assert(!strcmp(argv[0],OGW_GIT));assert(!strcmp(argv[9],"cat-file"));assert(!strcmp(argv[10],"tree"));assert(!strcmp(argv[11],oid));assert(argv[12]==NULL);
 frame.op=123;assert(!operation(&frame,oid,pack,argv,&offset,&length));
 uint8_t scope[192];memset(scope,1,sizeof(scope));int sockets[2];assert(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,sockets));assert(ogw_send(sockets[0],scope,1,OGW_INIT,NULL,0));uint8_t bytes[OGW_FRAME];ssize_t n=read(sockets[1],bytes,sizeof(bytes));assert(n==OGW_HEADER);assert(ogw_decode(bytes,(size_t)n,scope,1,&frame));assert(!ogw_decode(bytes,(size_t)n,scope,2,&frame));bytes[0]='X';assert(!ogw_decode(bytes,(size_t)n,scope,1,&frame));assert(!close(sockets[0])&&!close(sockets[1]));
 state=(ogw_state){0};assert(ogw_step(&state,OGW_INIT)&&ogw_step(&state,OGW_INDEX_PACK)&&ogw_step(&state,OGW_VERIFY_PACK)&&ogw_step(&state,OGW_FSCK)&&ogw_step(&state,OGW_SETTLE)&&ogw_step(&state,OGW_ADOPT));assert(!ogw_step(&state,OGW_SETTLE)&&!ogw_step(&state,OGW_ADOPT));
 process_sessions();puts("REAL production broker/Git/bundle/process/EOF/death paths; SYNTHETIC wire/state; NOT kernel isolation acceptance");return 0;
}
