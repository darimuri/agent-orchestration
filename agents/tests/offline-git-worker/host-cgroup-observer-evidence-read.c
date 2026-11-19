// Fixed observer-evidence reader. No mutation, execution, pathname input or admission.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <linux/magic.h>
#include <dirent.h>
#define OUTPUT_BOUND 524288U
#define BINARY_BOUND 34528U
#define RECEIPT_BOUND 16384U
#define VALUE_BOUND 4096U
#define OBJECTS 26U
#ifndef EVIDENCE_FIXTURE
static int io_root(void){return open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_NOATIME);}
static int io_open(int p,const char *name,int flags,bool cross){struct open_how h={.flags=(uint64_t)(unsigned)flags,.resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS};if(!cross)h.resolve|=RESOLVE_NO_XDEV;return (int)syscall(SYS_openat2,p,name,&h,sizeof(h));}
static int io_statx(int fd,struct statx *x){return (int)syscall(SYS_statx,fd,"",AT_EMPTY_PATH|AT_NO_AUTOMOUNT,STATX_BASIC_STATS|STATX_MNT_ID,x);}
#define IO_ROOT io_root
#define IO_OPEN io_open
#define IO_STAT fstat
#define IO_STATX io_statx
#define IO_FS fstatfs
#define IO_CLOSE close
#define IO_READ read
#define IO_WRITE write
#define IO_DENTS(fd,b,n) syscall(SYS_getdents64,(fd),(b),(n))
#define IO_FLAGS(fd) fcntl((fd),F_GETFL)
#endif
struct identity {struct stat st;uint64_t mount;};
struct node {int fd,parent;const char *name;mode_t exact;bool directory,cross,ordinary;struct identity before;};
struct object {const char *name,*status;size_t length;unsigned char *bytes;int node;bool after_valid;struct identity after;};
struct state {struct node nodes[48];unsigned count;struct object objects[OBJECTS];unsigned objects_seen;const char *error;int number;bool complete;};
struct dent {uint64_t ino;int64_t off;unsigned short len;unsigned char type;char name[];};
static unsigned char storage[3U*RECEIPT_BOUND+BINARY_BOUND+22U*VALUE_BOUND+OBJECTS];
static char output[OUTPUT_BOUND];
static bool fail(struct state *s,const char *error,int number){if(!s->error){s->error=error;s->number=number;}return false;}
#define NEED(s,p,e) do{if(!(p))return fail((s),(e),0);}while(0)
#define CALL(s,p,e) do{if((p)<0){int saved=errno;return fail((s),(e),saved);}}while(0)
static bool eligible(int argc,bool platform,uid_t u,uid_t eu,gid_t g,gid_t eg){return argc==1&&platform&&u==0&&eu==0&&g==0&&eg==0;}
static bool identify(struct state *s,int fd,bool directory,mode_t exact,struct identity *id){
 struct statx x;CALL(s,IO_STAT(fd,&id->st),"fstat");CALL(s,IO_STATX(fd,&x),"statx");id->mount=x.stx_mnt_id;
 NEED(s,(x.stx_mask&STATX_MNT_ID)&&id->st.st_uid==0&&id->st.st_gid==0&&!(id->st.st_mode&07022U),"custody");
 NEED(s,directory?S_ISDIR(id->st.st_mode):(S_ISREG(id->st.st_mode)&&id->st.st_nlink==1),"type_or_links");
 NEED(s,!exact||(id->st.st_mode&07777U)==exact,"mode");return true;
}
static bool equal(const struct identity *a,const struct identity *b){
 return a->st.st_dev==b->st.st_dev&&a->st.st_ino==b->st.st_ino&&a->mount==b->mount&&a->st.st_mode==b->st.st_mode&&a->st.st_uid==b->st.st_uid&&a->st.st_gid==b->st.st_gid&&a->st.st_nlink==b->st.st_nlink&&(a->st.st_size==b->st.st_size&&a->st.st_mtim.tv_sec==b->st.st_mtim.tv_sec&&a->st.st_mtim.tv_nsec==b->st.st_mtim.tv_nsec&&a->st.st_ctim.tv_sec==b->st.st_ctim.tv_sec&&a->st.st_ctim.tv_nsec==b->st.st_ctim.tv_nsec);
}
static int flags(bool directory,bool ordinary){return O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|(directory?O_DIRECTORY:0)|(ordinary?O_NOATIME:0);}
// -2 is explicitly missing. Every other error stops subsequent source IO.
static int add(struct state *s,int parent,const char *name,bool directory,bool cross,bool ordinary,mode_t exact){
 if(s->error)return -1;if(parent==-2)return -2;
 if(s->count>=48U){(void)fail(s,"node_bound",0);return -1;}
 int fd=parent<0?IO_ROOT():IO_OPEN(s->nodes[parent].fd,name,flags(directory,ordinary),cross);
 if(fd<0){int saved=errno;if(saved==ENOENT&&parent>=0)return -2;(void)fail(s,"openat2",saved);return -1;}
 unsigned index=s->count++;struct node *n=&s->nodes[index];n->fd=fd;n->parent=parent;n->name=name;n->exact=exact;n->directory=directory;n->cross=cross;n->ordinary=ordinary;
 if(!identify(s,fd,directory,exact,&n->before))return -1;
 if(parent>=0&&!cross&&(n->before.st.st_dev!=s->nodes[parent].before.st.st_dev||n->before.mount!=s->nodes[parent].before.mount)){(void)fail(s,"cross_device",0);return -1;}
 return (int)index;
}
static bool stable_node(struct state *s,int index,struct identity *after){
 struct node *n=&s->nodes[index];struct identity named;
 if(!identify(s,n->fd,n->directory,n->exact,after))return false;
 NEED(s,equal(&n->before,after),"held_identity");
 int fd=n->parent<0?IO_ROOT():IO_OPEN(s->nodes[n->parent].fd,n->name,flags(n->directory,n->ordinary),n->cross);
 if(fd<0){int saved=errno;return fail(s,"name_open",saved);}
 bool ok=identify(s,fd,n->directory,n->exact,&named);int closed=IO_CLOSE(fd),saved=errno;
 if(!ok)return false;if(closed<0)return fail(s,"close",saved);NEED(s,equal(after,&named),"name_identity");return true;
}
static bool stable(struct state *s){for(unsigned i=0;i<s->count;i++){struct identity after;if(!stable_node(s,(int)i,&after))return false;}return true;}
static bool cgroup(struct state *s,int index){if(index==-2)return true;if(index<0)return false;struct statfs fs;CALL(s,IO_FS(s->nodes[index].fd,&fs),"fstatfs");NEED(s,fs.f_type==CGROUP2_SUPER_MAGIC,"not_cgroup2");return true;}
static bool read_object(struct state *s,unsigned at,int parent,const char *name,size_t bound,bool ordinary,mode_t exact){
 struct object *o=&s->objects[at];o->status="unread";o->node=add(s,parent,name,false,false,ordinary,exact);s->objects_seen=at+1U;
 if(o->node==-2){o->status="missing";return true;}if(o->node<0){o->status="unsafe";return false;}
 o->status="partial";struct identity before;if(!stable_node(s,o->node,&before))return false;
 ssize_t got=IO_READ(s->nodes[o->node].fd,o->bytes,bound+1U);
 if(got<0){int saved=errno;return fail(s,"read",saved);}o->length=(size_t)got;
 NEED(s,o->length<=bound,"read_bound");if(at==3U)NEED(s,o->length==BINARY_BOUND,"observer_size");unsigned char extra;
 ssize_t tail=IO_READ(s->nodes[o->node].fd,&extra,1U);if(tail<0){int saved=errno;return fail(s,"read_tail",saved);}NEED(s,tail==0,"short_or_growing_read");
 if(!stable_node(s,o->node,&o->after))return false;o->after_valid=true;
 NEED(s,!ordinary||(before.st.st_size>=0&&(uint64_t)before.st.st_size==o->length),"short_read");o->status="ok";return true;
}
static bool directory(struct state *s,int parent,unsigned index,bool allow_leaf){
 struct object *o=&s->objects[index];o->node=parent;o->status="unread";s->objects_seen=index+1U;
 if(parent==-2){o->status="missing";return true;}if(parent<0){o->status="unsafe";return false;}
 o->status="partial";struct identity before;if(!stable_node(s,parent,&before))return false;
 // getdents64 leaves record alignment padding untouched; raw export includes it.
 _Alignas(uint64_t) unsigned char buf[VALUE_BOUND]={0},tail[VALUE_BOUND]={0};long got=IO_DENTS(s->nodes[parent].fd,buf,sizeof(buf));
 if(got<0){int saved=errno;return fail(s,"getdents",saved);}NEED(s,(unsigned long)got<=VALUE_BOUND,"directory_bound");
 o->length=(size_t)got;memcpy(o->bytes,buf,o->length);
 long more=IO_DENTS(s->nodes[parent].fd,tail,sizeof(tail));if(more<0){int saved=errno;return fail(s,"getdents_tail",saved);}NEED(s,more==0,"directory_bound");
 bool descendants=false;size_t at=0;while(at<o->length){size_t fixed=offsetof(struct dent,name);NEED(s,o->length-at>=fixed+1U,"directory_encoding");struct dent *d=(struct dent *)(void *)(buf+at);NEED(s,d->len>=fixed+1U&&d->len%8U==0U&&d->len<=o->length-at&&memchr(d->name,0,(size_t)d->len-fixed),"directory_encoding");
  bool dots=!strcmp(d->name,".")||!strcmp(d->name,"..");bool fixed_leaf=allow_leaf&&d->type==DT_DIR&&!strcmp(d->name,"cgroup-observe-v1");if(dots?d->type!=DT_DIR:(d->type!=DT_REG&&!fixed_leaf))descendants=true;at+=d->len;
 }
 if(!stable_node(s,parent,&o->after))return false;o->after_valid=true;o->status=descendants?"unexpected_entries":"ok";return true;
}
static bool snapshot(struct state *s){
 // Only literal fixed anchors; missing fixture stages do not authorize creation.
 int root=add(s,-1,"/",true,true,true,0);if(root<0)return false;
 int var=add(s,root,"var",true,true,true,0);if(var==-1)return false;
 int lib=add(s,var,"lib",true,true,true,0);if(lib==-1)return false;
 int top=add(s,lib,"age30-qualification",true,false,true,0700);if(top==-1)return false;
 int evidence=add(s,top,"evidence",true,false,true,0700);if(evidence==-1)return false;
 int journal=add(s,evidence,"age30-8bbc3a9d-r1-cgroup-observe-v1",true,false,true,0700);if(journal==-1)return false;
 const char *const reports[]={"start.json","observations.json","result.json"};for(unsigned i=0;i<3U;i++)if(!read_object(s,i,journal,reports[i],RECEIPT_BOUND,true,0600))return false;
 int bin=add(s,top,"bin",true,false,true,0700);if(bin==-1)return false;
 if(!read_object(s,3,bin,"cgroup-observe-v1",BINARY_BOUND,true,0500))return false;
 int sys=add(s,root,"sys",true,true,true,0);if(sys==-1)return false;
 int fs=add(s,sys,"fs",true,true,true,0);if(fs==-1)return false;
 int cg=add(s,fs,"cgroup",true,true,false,0);if(!cgroup(s,cg))return false;
 if(!read_object(s,4,cg,"cgroup.controllers",VALUE_BOUND,false,0)||!read_object(s,5,cg,"cgroup.subtree_control",VALUE_BOUND,false,0))return false;
 int parent=add(s,cg,"age30-qualification-age30-8bbc3a9d-r1",true,false,false,0700);if(!cgroup(s,parent))return false;
 const char *const values[]={"cgroup.type","cgroup.controllers","cgroup.subtree_control","cgroup.procs","cgroup.events"};for(unsigned i=0;i<5U;i++)if(!read_object(s,6U+i,parent,values[i],VALUE_BOUND,false,0))return false;
 if(!directory(s,parent,11U,true))return false;
 int leaf=add(s,parent,"cgroup-observe-v1",true,false,false,0700);if(!cgroup(s,leaf))return false;
 const char *const leaf_values[]={"cgroup.type","cgroup.events","cgroup.procs","cpu.max","cpu.max.burst","memory.max","memory.swap.max","memory.oom.group","pids.max","cpu.stat","memory.current","memory.events","pids.current"};
 for(unsigned i=0;i<13U;i++)if(!read_object(s,12U+i,leaf,leaf_values[i],VALUE_BOUND,false,0))return false;
 return directory(s,leaf,25U,false)&&stable(s);
}
static bool append(size_t *used,const char *format,...){va_list args;va_start(args,format);int n=vsnprintf(output+*used,sizeof(output)-*used,format,args);va_end(args);if(n<0||(size_t)n>=sizeof(output)-*used)return false;*used+=(size_t)n;return true;}
static bool metadata(size_t *used,const struct identity *id){return append(used,"{\"dev\":\"%llu\",\"ino\":\"%llu\",\"mount\":\"%llu\",\"mode\":%u,\"uid\":%u,\"gid\":%u,\"nlink\":\"%llu\",\"size\":\"%lld\",\"mtimeSec\":\"%lld\",\"mtimeNsec\":%ld,\"ctimeSec\":\"%lld\",\"ctimeNsec\":%ld}",(unsigned long long)id->st.st_dev,(unsigned long long)id->st.st_ino,(unsigned long long)id->mount,(unsigned)(id->st.st_mode&07777U),(unsigned)id->st.st_uid,(unsigned)id->st.st_gid,(unsigned long long)id->st.st_nlink,(long long)id->st.st_size,(long long)id->st.st_mtim.tv_sec,id->st.st_mtim.tv_nsec,(long long)id->st.st_ctim.tv_sec,id->st.st_ctim.tv_nsec);}
static bool base64(size_t *used,const unsigned char *b,size_t n){const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";if(n>(OUTPUT_BOUND-*used)/4U*3U)return false;for(size_t i=0;i<n;i+=3U){unsigned v=(unsigned)b[i]<<16U;if(i+1U<n)v|=(unsigned)b[i+1U]<<8U;if(i+2U<n)v|=b[i+2U];if(!append(used,"%c%c%c%c",alphabet[(v>>18U)&63U],alphabet[(v>>12U)&63U],i+1U<n?alphabet[(v>>6U)&63U]:'=',i+2U<n?alphabet[v&63U]:'='))return false;}return true;}
static bool render(struct state *s,size_t *used){
 *used=0;if(!append(used,"{\"version\":1,\"status\":\"UNKNOWN\",\"admission\":false,\"qualified\":false,\"assumptionsVerified\":false,\"collectionComplete\":%s,\"atomic\":false,\"cgroupDurability\":\"RUNTIME_ONLY\",\"error\":\"%s\",\"errorErrno\":%d,\"objects\":[",s->complete?"true":"false",s->error?s->error:"none",s->number))return false;
 for(unsigned i=0;i<OBJECTS;i++){struct object *o=&s->objects[i];if(!append(used,"%s{\"name\":\"%s\",\"status\":\"%s\",\"size\":%zu,\"before\":",i?",":"",o->name,o->status,o->length))return false;
  if(o->node>=0){if(!metadata(used,&s->nodes[o->node].before))return false;}else if(!append(used,"null"))return false;
  if(!append(used,",\"after\":"))return false;if(o->after_valid){if(!metadata(used,&o->after))return false;}else if(!append(used,"null"))return false;
  if(!append(used,",\"base64\":\"")||!base64(used,o->bytes,o->length)||!append(used,"\"}"))return false;
 }return append(used,"]}\n");
}
static bool output_pipe(struct state *s){struct stat st;struct statfs fs;CALL(s,IO_STAT(1,&st),"stdout_stat");CALL(s,IO_FS(1,&fs),"stdout_fs");int f=IO_FLAGS(1);if(f<0){int saved=errno;return fail(s,"stdout_flags",saved);}NEED(s,S_ISFIFO(st.st_mode)&&fs.f_type==0x50495045&&st.st_uid!=0&&(f&O_ACCMODE)==O_WRONLY,"stdout_pipe");return true;}
static int collect(void){
 struct state s;memset(&s,0,sizeof(s));
 const char *const names[]={"run.start","run.observations","run.result","observer","root.controllers","root.subtree_control","parent.type","parent.controllers","parent.subtree_control","parent.procs","parent.events","parent.entries","leaf.type","leaf.events","leaf.procs","leaf.cpu.max","leaf.cpu.max.burst","leaf.memory.max","leaf.memory.swap.max","leaf.memory.oom.group","leaf.pids.max","leaf.cpu.stat","leaf.memory.current","leaf.memory.events","leaf.pids.current","leaf.entries"};size_t offset=0;
 for(unsigned i=0;i<OBJECTS;i++){s.objects[i].name=names[i];s.objects[i].status="unread";s.objects[i].node=-1;s.objects[i].bytes=storage+offset;offset+=(i<3U?RECEIPT_BOUND:i==3U?BINARY_BOUND:VALUE_BOUND)+1U;}
 if(!output_pipe(&s))return 2;s.complete=snapshot(&s);size_t used;
 if(!render(&s,&used)){const char fallback[]="{\"version\":1,\"status\":\"UNKNOWN\",\"admission\":false,\"qualified\":false,\"assumptionsVerified\":false,\"collectionComplete\":false,\"error\":\"output_bound\"}\n";memcpy(output,fallback,sizeof(fallback)-1U);used=sizeof(fallback)-1U;}
 // All source reads finish before the first output write. No retry on short/EINTR/EPIPE.
 for(size_t at=0;at<used;){size_t n=used-at;if(n>4096U)n=4096U;ssize_t wrote=IO_WRITE(1,output+at,n);if(wrote!=(ssize_t)n)break;at+=n;}
 for(unsigned i=0;i<s.count;i++)(void)close(s.nodes[i].fd);return 2;
}
#ifndef EVIDENCE_FIXTURE
int main(int argc,char **argv){(void)argv;struct utsname u;bool platform=uname(&u)==0&&!strcmp(u.sysname,"Linux")&&!strcmp(u.machine,"x86_64");if(!eligible(argc,platform,getuid(),geteuid(),getgid(),getegid()))return 2;
 if(syscall(SYS_close_range,3U,UINT_MAX,0U)||clearenv())return 2;(void)close(0);if(signal(SIGPIPE,SIG_IGN)==SIG_ERR)return 2;return collect();}
#endif
