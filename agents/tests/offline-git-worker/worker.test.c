// SYNTHETIC wire/state/dispatch tests; never launches a generic command.
#define OGW_TEST 1
#include "../../offline-git-worker/native/worker.c"
#include "../../offline-git-worker/native/custody.c"
#include <assert.h>
int main(void){
 (void)worker;ogw_state state={0};assert(ogw_step(&state,OGW_INIT));assert(ogw_step(&state,OGW_INDEX_PACK));assert(ogw_step(&state,OGW_VERIFY_PACK));assert(ogw_step(&state,OGW_FSCK));
 for(unsigned i=0;i<OGW_READS;i++)assert(ogw_step(&state,OGW_OBJECT_READ));assert(!ogw_step(&state,OGW_OBJECT_READ));assert(!ogw_step(&state,OGW_SETTLE));
 state=(ogw_state){0};assert(ogw_charge(&state,OGW_MACHINE,OGW_DIAGNOSTICS));assert(!ogw_charge(&state,1,0));
 state=(ogw_state){0};assert(!ogw_step(&state,OGW_FSCK));
 ogw_frame frame;memset(&frame,0,sizeof(frame));frame.op=OGW_TREE;memset(frame.payload,0xab,20);frame.n=20;
 char oid[41],pack[128]={0},*argv[20];uint64_t offset,length;assert(operation(&frame,oid,pack,argv,&offset,&length));assert(!strcmp(oid,"abababababababababababababababababababab"));assert(!strcmp(argv[0],OGW_GIT));assert(!strcmp(argv[9],"cat-file"));assert(!strcmp(argv[10],"tree"));assert(!strcmp(argv[11],oid));assert(argv[12]==NULL);
 frame.op=123;assert(!operation(&frame,oid,pack,argv,&offset,&length));
 uint8_t scope[192];memset(scope,1,sizeof(scope));int sockets[2];assert(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,sockets));assert(ogw_send(sockets[0],scope,1,OGW_INIT,NULL,0));uint8_t bytes[OGW_FRAME];ssize_t n=read(sockets[1],bytes,sizeof(bytes));assert(n==OGW_HEADER);assert(ogw_decode(bytes,(size_t)n,scope,1,&frame));assert(!ogw_decode(bytes,(size_t)n,scope,2,&frame));bytes[0]='X';assert(!ogw_decode(bytes,(size_t)n,scope,1,&frame));assert(!close(sockets[0])&&!close(sockets[1]));
 puts("SYNTHETIC wire/state/fixed dispatch; NOT kernel isolation acceptance");return 0;
}
