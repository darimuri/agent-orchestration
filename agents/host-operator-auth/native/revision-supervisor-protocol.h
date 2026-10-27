#ifndef REVISION_SUPERVISOR_PROTOCOL_H
#define REVISION_SUPERVISOR_PROTOCOL_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#define RS_FRAME_MAX 16384U
#define RS_INPUT_MAX 8192U
#define RS_OUTPUT_MAX 4096U
#define RS_PATH_MAX 4096U
#define RS_ID_MAX 128U
#ifndef RS_UID
#define RS_UID 1000U
#endif
#define RS_GO 0x47U
#define RS_CLEANUP_MS 2000U
#define RS_MAX_EPOCH UINT64_C(9007199254740991)
/* Wire integers are network order, never native structs/padding. No JSON in C. */
typedef struct { uint8_t *p;
 size_t n, at;
 bool ok;
 } rs_wire;
static inline uint64_t rs_get(rs_wire *w, size_t n) {
  uint64_t v=0U;
 if(!w->ok||n>8U||w->at>w->n||n>w->n-w->at){w->ok=false;
return 0U;
}
  for(size_t i=0U;i<n;i++)v=(v<<8U)|w->p[w->at++];
return v;
}
static inline void rs_put(rs_wire *w,uint64_t v,size_t n){
  if(!w->ok||n>8U||w->at>w->n||n>w->n-w->at){w->ok=false;
return;
}
  for(size_t i=0U;i<n;i++){w->p[w->at+n-i-1U]=(uint8_t)(v&255U);
v>>=8U;
}w->at+=n;
}
static inline void rs_bytes(rs_wire *w,void *out,size_t n){if(!w->ok||w->at>w->n||n>w->n-w->at){w->ok=false;
return;
}memcpy(out,w->p+w->at,n);
w->at+=n;
}
static inline void rs_emit(rs_wire *w,const void *in,size_t n){if(!w->ok||w->at>w->n||n>w->n-w->at){w->ok=false;
return;
}memcpy(w->p+w->at,in,n);
w->at+=n;
}
static inline size_t rs_string(rs_wire *w,char *out,size_t max){size_t n=(size_t)rs_get(w,2U);
if(n==0U||n>max){w->ok=false;
return 0U;
}rs_bytes(w,out,n);
if(!w->ok)return 0U;
out[n]='\0';
if(memchr(out,'\0',n)!=NULL)w->ok=false;
return n;
}
static inline void rs_text(rs_wire *w,const char *s){size_t n=strlen(s);
rs_put(w,(uint64_t)n,2U);
rs_emit(w,s,n);
}
/* Fixed reasons are diagnostic only, never settlement authority. */
enum rs_reason { RS_OK=0,RS_PROTOCOL=1,RS_CONTEXT=2,RS_COLLISION=3,RS_CLONE=4,RS_CANCEL=5,RS_CLOCK=6,RS_OVERFLOW=7,RS_IDENTITY=8,RS_REAP=9,RS_REMOVE=10,RS_IO=11,RS_LOCK=12 };
typedef struct {
  char run[RS_ID_MAX+1U],clock[RS_ID_MAX+1U],runtime[RS_PATH_MAX+1U],worker[RS_PATH_MAX+1U];
  uint8_t request[32],intent[32],worker_hash[32],input[RS_INPUT_MAX];
  uint64_t started,deadline,dev[2],ino[2],size[2];
uint32_t wait_ms;
size_t input_n;
} rs_request;
typedef struct {
  uint8_t status,boundary[32],reaped,no_escape,sealed,populated,cleanup;
  uint16_t reason,signal;
int32_t exit_code;
  uint64_t exited,settled,root_dev,root_ino,child_dev,child_ino;
  uint8_t out[RS_OUTPUT_MAX],err[RS_OUTPUT_MAX];
size_t out_n,err_n;
} rs_terminal;
#endif
