#ifndef OGW_PROTOCOL_H
#define OGW_PROTOCOL_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#define OGW_HEADER 208U
#define OGW_CONTROL 16384U
#define OGW_FRAME 65536U
#define OGW_BUNDLE 33554432U
#define OGW_OBJECT 8388608U
#define OGW_MACHINE 268435456U
#define OGW_DIAGNOSTICS 1048576U
#define OGW_READS 20000U
#define OGW_FRAMES 65536U
#define OGW_MEMORY 536870912U
#define OGW_SCRATCH 268435456U
#define OGW_INODES 65536U
#define OGW_WORK_MS 30000U
#define OGW_SETTLE_MS 2000U
#define OGW_OUTER_MS 40000U
#define OGW_CPU_GUARD 8000000U
#define OGW_CPU_FINAL 10000000U
#define OGW_UID 10002U
#define OGW_HOST_UID 1000U
#define OGW_ROOT "/var/lib/github-app-agent-gateway/offline-import-v1"
#define OGW_VALIDATOR "/validator/entry.mjs"
#define OGW_GIT "/usr/bin/git"
#define OGW_NODE "/usr/bin/node"
enum ogw_op { OGW_OPEN=1,OGW_INIT,OGW_INDEX_PACK,OGW_VERIFY_PACK,OGW_FSCK,
 OGW_OBJECT_READ,OGW_TREE,OGW_SETTLE,OGW_ADOPT,OGW_OBSERVE,OGW_DATA,OGW_END,OGW_DENIED,OGW_UNKNOWN };
typedef struct { uint8_t binding[192]; uint32_t seq,op,n; uint8_t payload[OGW_FRAME-OGW_HEADER]; } ogw_frame;
typedef struct { unsigned stage,reads,frames; uint64_t machine,diagnostics; bool poisoned; } ogw_state;
static inline uint64_t ogw_get(const uint8_t *b,size_t n){uint64_t v=0;for(size_t i=0;i<n;i++)v=(v<<8)|b[i];return v;}
static inline void ogw_put(uint8_t *b,uint64_t v,size_t n){for(size_t i=0;i<n;i++){b[n-i-1U]=(uint8_t)(v&255U);v>>=8;}}
static inline bool ogw_payload(unsigned op,const uint8_t *p,size_t n){
 switch(op){
 case OGW_OPEN:case OGW_ADOPT:return n==32U;
 case OGW_INDEX_PACK:return n==16U&&ogw_get(p,8)<=OGW_BUNDLE&&ogw_get(p+8,8)>0U&&ogw_get(p+8,8)<=OGW_BUNDLE-ogw_get(p,8);
 case OGW_OBJECT_READ:case OGW_TREE:return n==20U;
 case OGW_INIT:case OGW_VERIFY_PACK:case OGW_FSCK:case OGW_SETTLE:case OGW_OBSERVE:case OGW_END:case OGW_DENIED:case OGW_UNKNOWN:return n==0U;
 case OGW_DATA:return n<=OGW_FRAME-OGW_HEADER;
 default:return false;
 }
}
static inline bool ogw_decode(const uint8_t *b,size_t n,const uint8_t binding[192],uint32_t seq,ogw_frame *f){
 if(n<OGW_HEADER||n>OGW_FRAME||memcmp(b,"OGW1",4)||ogw_get(b+4,2)!=1U||seq==0U||ogw_get(b+8,4)!=seq||ogw_get(b+12,4)!=n-OGW_HEADER||memcmp(b+16,binding,192))return false;
 unsigned op=(unsigned)ogw_get(b+6,2);size_t payload=n-OGW_HEADER;
 if(!ogw_payload(op,b+OGW_HEADER,payload)||(op!=OGW_DATA&&n>OGW_CONTROL))return false;
 memcpy(f->binding,binding,192);f->seq=seq;f->op=op;f->n=(uint32_t)payload;memcpy(f->payload,b+OGW_HEADER,payload);return true;
}
static inline bool ogw_send(int fd,const uint8_t binding[192],uint32_t seq,unsigned op,const uint8_t *payload,size_t n){
 uint8_t b[OGW_FRAME];if(!ogw_payload(op,payload,n)||seq==0U)return false;
 memcpy(b,"OGW1",4);ogw_put(b+4,1,2);ogw_put(b+6,op,2);ogw_put(b+8,seq,4);ogw_put(b+12,n,4);memcpy(b+16,binding,192);if(n)memcpy(b+OGW_HEADER,payload,n);
 ssize_t r;do{r=write(fd,b,OGW_HEADER+n);}while(r<0&&errno==EINTR);return r>=0&&(size_t)r==OGW_HEADER+n;
}
static inline bool ogw_step(ogw_state *s,unsigned op){
 if(s->poisoned)return false;
 const unsigned stages[4]={OGW_INIT,OGW_INDEX_PACK,OGW_VERIFY_PACK,OGW_FSCK};
 if(s->stage<4U&&op==stages[s->stage]){s->stage++;return true;}
 if(s->stage==4U&&(op==OGW_OBJECT_READ||op==OGW_TREE)&&++s->reads<=OGW_READS)return true;
 if(s->stage==4U&&op==OGW_SETTLE){s->stage=5U;return true;}
 s->poisoned=true;return false;
}
static inline bool ogw_charge(ogw_state *s,size_t out,size_t err){
 if(s->poisoned||++s->frames>OGW_FRAMES||out>OGW_MACHINE-s->machine||err>OGW_DIAGNOSTICS-s->diagnostics){s->poisoned=true;return false;}
 s->machine+=out;s->diagnostics+=err;return true;
}
#endif
